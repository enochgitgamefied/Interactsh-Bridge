package interactshbridge;

import burp.api.montoya.*;
import com.google.gson.*;
import com.sun.net.httpserver.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.swing.*;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import static interactshbridge.InteractshClient.*;

public final class BridgeTests {
    static int checks;
    static void check(boolean value,String label){checks++;if(!value)throw new AssertionError(label);}
    interface Work{void run()throws Exception;}
    static void fails(Work w,String label)throws Exception{try{w.run();}catch(Exception e){checks++;return;}throw new AssertionError(label);}
    static Config config(String url){return new Config(url,"test-token",20,13,1,3);}
    static JsonObject interaction(String p,String id){JsonObject d=new JsonObject();d.addProperty("protocol",p);d.addProperty("unique-id",id);d.addProperty("full-id",id+".example.invalid");d.addProperty("timestamp","2026-09-11T09:15:20Z");d.addProperty("remote-address","192.0.2.15");d.addProperty("raw-request","GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\n");d.addProperty("raw-response","HTTP/1.1 200 OK\r\n\r\nCaptured callback");return d;}
    static byte[] encrypt(byte[] key,String mode,String text)throws Exception{byte[] iv=new byte[16];RANDOM.nextBytes(iv);Cipher c=Cipher.getInstance("AES/"+mode+"/NoPadding");c.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(key,"AES"),new IvParameterSpec(iv));ByteArrayOutputStream out=new ByteArrayOutputStream();out.write(iv);out.write(c.doFinal(text.getBytes(StandardCharsets.UTF_8)));return out.toByteArray();}
    static class Mock implements AutoCloseable{
        final HttpServer server;final ExecutorService workers=Executors.newCachedThreadPool();final Map<String,JsonObject> sessions=new ConcurrentHashMap<>();
        final AtomicInteger flight=new AtomicInteger(),maxFlight=new AtomicInteger();volatile int status=200,delay;volatile boolean malformed,deny;
        Mock()throws IOException{
            server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);server.setExecutor(workers);
            server.createContext("/register",e->handle(e,()->{if(deny||!"test-token".equals(e.getRequestHeaders().getFirst("Authorization"))){reply(e,403,"{}");return;}JsonObject d=read(e);if(sessions.putIfAbsent(text(d,"correlation-id"),d)!=null){reply(e,400,"{}");return;}reply(e,200,"{\"message\":\"registration successful\"}");}));
            server.createContext("/poll",e->handle(e,()->{int n=flight.incrementAndGet();maxFlight.accumulateAndGet(n,Math::max);try{
                if(delay>0)Thread.sleep(delay);if(status!=200){reply(e,status,"{}");return;}if(malformed){reply(e,200,"not-json");return;}
                Map<String,String> q=new HashMap<>();for(String part:e.getRequestURI().getRawQuery().split("&")){String[] a=part.split("=",2);q.put(a[0],URLDecoder.decode(a[1],StandardCharsets.UTF_8));}JsonObject reg=sessions.get(q.get("id"));
                if(reg==null||!text(reg,"secret-key").equals(q.get("secret"))){reply(e,401,"{}");return;}
                String pem=new String(Base64.getDecoder().decode(text(reg,"public-key")),StandardCharsets.US_ASCII).replaceAll("-----[^\\n]+-----","").replaceAll("\\s","");PublicKey pub=KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(pem)));
                byte[] key=new byte[32];RANDOM.nextBytes(key);Cipher rsa=Cipher.getInstance("RSA/ECB/OAEPPadding");rsa.init(Cipher.ENCRYPT_MODE,pub,new OAEPParameterSpec("SHA-256","MGF1",MGF1ParameterSpec.SHA256,PSource.PSpecified.DEFAULT));JsonObject r=new JsonObject();r.addProperty("aes_key",Base64.getEncoder().encodeToString(rsa.doFinal(key)));
                JsonArray data=new JsonArray();data.add(Base64.getEncoder().encodeToString(encrypt(key,"CTR",interaction("http",q.get("id")).toString())));data.add("malformed");r.add("data",data);JsonArray extra=new JsonArray();extra.add(interaction("dns",q.get("id")+"dns").toString());r.add("extra",extra);JsonArray tld=new JsonArray();tld.add(interaction("smtp",q.get("id")+"mail").toString());r.add("tlddata",tld);reply(e,200,r.toString());
            }finally{flight.decrementAndGet();}}));
            server.createContext("/deregister",e->handle(e,()->{sessions.remove(text(read(e),"correlation-id"));reply(e,200,"{}");}));server.start();
        }
        String url(){return "http://127.0.0.1:"+server.getAddress().getPort();}public void close(){server.stop(0);workers.shutdownNow();}
    }
    static void handle(HttpExchange e,Work w){try{w.run();}catch(Throwable ex){try{reply(e,500,"{}");}catch(Exception ignore){e.close();}}}
    static JsonObject read(HttpExchange e)throws IOException{return JsonParser.parseString(new String(e.getRequestBody().readAllBytes(),StandardCharsets.UTF_8)).getAsJsonObject();}
    static void reply(HttpExchange e,int status,String text)throws IOException{byte[] b=text.getBytes(StandardCharsets.UTF_8);e.getResponseHeaders().set("Content-Type","application/json");e.sendResponseHeaders(status,b.length);try(var out=e.getResponseBody()){out.write(b);}}
    public static void main(String[] args)throws Exception{
        fails(()->config("https://example.invalid/path"),"path rejected");fails(()->config("https://name:pass@example.invalid"),"URL credentials rejected");fails(()->new Config("https://example.invalid","",50,20,5,30),"DNS label bound");fails(()->new Config("https://example.invalid","",20,13,0,30),"interval bound");
        Session session=create(config("https://example.invalid"));check(session.address().split("\\.")[0].length()==33,"address length");check(!session.address().equals(session.address()),"nonce uniqueness");byte[] key=new byte[32];RANDOM.nextBytes(key);
        for(String mode:List.of("CTR","CFB","OFB"))check(text(decrypt(key,Base64.getEncoder().encodeToString(encrypt(key,mode,interaction("dns","fixture").toString()))),"unique-id").equals("fixture"),mode+" fixture");fails(()->decrypt(key,"AA=="),"short cipher rejected");
        byte[] saved=SessionFile.encode(session,"long test password".toCharArray());check(!new String(saved,StandardCharsets.UTF_8).contains(session.secret()),"credentials encrypted");Session opened=SessionFile.decode(saved,"long test password".toCharArray());check(opened.id().equals(session.id())&&opened.config().equals(session.config()),"session roundtrip");fails(()->SessionFile.decode(saved,"incorrect".toCharArray()),"wrong password");fails(()->SessionFile.encode(session,"short".toCharArray()),"short password");
        InteractionStore store=new InteractionStore(2);Poll one=new Poll(List.of(interaction("dns","same")),0);check(store.add(session,one)==1&&store.add(session,one)==0,"deduplication");store.add(session,new Poll(List.of(interaction("http","same"),interaction("smtp","other")),0));check(store.values().size()==2&&store.evicted==1,"retention cap");check(!store.export("notes").toString().contains(session.secret()),"export excludes secrets");
        try(Mock mock=new Mock()){
            Session local=create(config(mock.url()));try(InteractshClient c=new InteractshClient(local)){
                c.register();check(mock.sessions.containsKey(local.id()),"registered");Poll p=c.poll();check(p.interactions().size()==3&&p.rejected()==1,"encrypted and plaintext records");check(c.resume().interactions().size()==3,"resume live session");mock.sessions.clear();check(c.resume().interactions().size()==3,"resume expired session");
                mock.status=401;fails(c::poll,"auth error");mock.status=302;fails(c::poll,"redirect rejected");mock.status=200;mock.malformed=true;fails(c::poll,"malformed response");mock.malformed=false;c.deregister();check(!mock.sessions.containsKey(local.id()),"deregistered");
            }
            mock.deny=true;try(InteractshClient c=new InteractshClient(create(config(mock.url())))){fails(c::register,"registration denied");}mock.deny=false;
            List<Runnable> tasks=new CopyOnWriteArrayList<>();AtomicInteger events=new AtomicInteger();AtomicBoolean ready=new AtomicBoolean(),polled=new AtomicBoolean();AtomicReference<String> error=new AtomicReference<>();
            SessionController controller=new SessionController(tasks::add,new SessionController.Listener(){public void connected(Session s,Poll p){events.incrementAndGet();ready.set(true);}public void polled(Poll p){events.incrementAndGet();polled.set(true);}public void error(String s){error.set(s);}});
            try{controller.connect(config(mock.url()),null);until(tasks,ready::get);check(controller.session()!=null,"validated connection");mock.delay=150;for(int i=0;i<15;i++)controller.pollNow();until(tasks,polled::get);check(mock.maxFlight.get()==1,"no overlapping polls");int before=events.get();controller.pollNow();Thread.sleep(30);controller.disconnect(true);Thread.sleep(200);drain(tasks);check(events.get()==before&&controller.session()==null,"late events dropped");}finally{controller.close();}
        }
        ui(session);System.out.println("PASS: "+checks+" checks");
    }
    static void drain(List<Runnable> tasks){for(Runnable r:List.copyOf(tasks)){tasks.remove(r);r.run();}}
    static void until(List<Runnable> tasks,java.util.function.BooleanSupplier condition)throws Exception{long end=System.nanoTime()+TimeUnit.SECONDS.toNanos(8);while(!condition.getAsBoolean()&&System.nanoTime()<end){drain(tasks);Thread.sleep(20);}if(!condition.getAsBoolean())throw new AssertionError("Controller event timed out");}
    static Object proxy(Class<?> type,java.util.function.BiFunction<java.lang.reflect.Method,Object[],Object> f){return java.lang.reflect.Proxy.newProxyInstance(type.getClassLoader(),new Class[]{type},(p,m,a)->f.apply(m,a));}
    static void ui(Session session)throws Exception{
        AtomicReference<BridgePanel> ref=new AtomicReference<>();AtomicReference<Runnable> unload=new AtomicReference<>();Map<String,String> prefs=new HashMap<>();
        MontoyaApi api=(MontoyaApi)proxy(MontoyaApi.class,(m,a)->proxy(m.getReturnType(),(method,arguments)->{
            if(method.getName().equals("preferences"))return proxy(method.getReturnType(),(pm,pa)->{if(pm.getName().equals("getString"))return prefs.get((String)pa[0]);if(pm.getName().equals("setString"))prefs.put((String)pa[0],(String)pa[1]);return null;});
            if(method.getName().equals("registerSuiteTab"))ref.set((BridgePanel)arguments[1]);if(method.getName().equals("registerUnloadingHandler"))unload.set(()->((burp.api.montoya.extension.ExtensionUnloadingHandler)arguments[0]).extensionUnloaded());return null;}));
        new BridgeExtension().initialize(api);check(ref.get()!=null,"Montoya tab registration");
        SwingUtilities.invokeAndWait(()->{BridgePanel p=ref.get();check(!p.poll.isEnabled(),"disconnected controls");p.store.add(session,new Poll(List.of(interaction("http","http-record"),interaction("dns","dns-record"),interaction("smtp","mail-record")),0));p.refresh();check(p.table.getRowCount()==3,"table populated");p.protocol.setSelectedItem("DNS");check(p.table.getRowCount()==1,"protocol filter");p.protocol.setSelectedIndex(0);p.search.setText("http-record");check(p.table.getRowCount()==1,"raw search");p.search.setText("");p.table.setRowSelectionInterval(0,0);check(p.raw.getText().contains("mail-record")&&p.request.getText().startsWith("GET"),"JSON and request details");p.mode.setSelectedIndex(1);check(p.token.isEnabled(),"custom token available");p.token.setText("secret");p.mode.setSelectedIndex(0);check(p.token.getPassword().length==0,"public token cleared");p.setSize(1400,950);((JTabbedPane)p.getComponent(0)).setSelectedIndex(0);p.address.setText(session.address());p.notes.setText("Synthetic preview; local fixtures only.");snapshot(p,"work/ui-preview.png");((JTabbedPane)p.getComponent(0)).setSelectedIndex(1);snapshot(p,"work/ui-connection.png");unload.get().run();});
    }
    static void layout(Container p){p.doLayout();for(Component c:p.getComponents())if(c instanceof Container child)layout(child);}
    static void snapshot(BridgePanel p,String path){layout(p);layout(p);BufferedImage image=new BufferedImage(p.getWidth(),p.getHeight(),BufferedImage.TYPE_INT_RGB);Graphics2D g=image.createGraphics();p.printAll(g);g.dispose();try{javax.imageio.ImageIO.write(image,"png",new File(path));}catch(IOException ex){throw new RuntimeException(ex);}}
}
