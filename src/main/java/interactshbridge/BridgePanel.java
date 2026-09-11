package interactshbridge;

import burp.api.montoya.MontoyaApi;
import com.google.gson.*;
import javax.swing.*;
import javax.swing.event.*;
import javax.swing.table.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.nio.file.*;
import java.util.*;
import java.util.List;
import java.util.concurrent.*;
import static interactshbridge.InteractshClient.*;

final class BridgePanel extends JPanel {
    private final MontoyaApi api;
    final InteractionStore store = new InteractionStore(5000);
    final JComboBox<String> mode = new JComboBox<>(new String[]{"Public Interactsh", "Custom server"});
    final JComboBox<String> server = new JComboBox<>(PUBLIC.toArray(String[]::new));
    final JPasswordField token = new JPasswordField(18);
    final JSpinner idLength = number(20, 3, 60), nonceLength = number(13, 3, 60), interval = number(5, 1, 300), timeout = number(30, 1, 120);
    final JButton connect = button("Connect"), disconnect = button("Disconnect"), poll = button("Poll now"), generate = button("New address"), copy = button("Copy address");
    private final JButton saveSession = button("Save session…"), resume = button("Resume session…");
    final JTextField address = new JTextField(), search = new JTextField(20);
    final JComboBox<String> protocol = new JComboBox<>(new String[]{"All protocols", "DNS", "HTTP", "SMTP", "LDAP", "FTP", "SMB", "Other"});
    final JLabel status = new JLabel("Disconnected · Choose a server to begin"), lastPoll = new JLabel("Last poll: —"), count = new JLabel("0 interactions");
    final JTextArea request = area(), response = area(), details = area(), raw = area(), notes = area();
    final JTabbedPane detailTabs = new JTabbedPane();
    private final DefaultTableModel rows = new DefaultTableModel(new String[]{"Protocol", "Time", "Remote address", "Interaction ID", "Server"}, 0) { @Override public boolean isCellEditable(int r, int c) { return false; } };
    final JTable table = new JTable(rows);
    private final TableRowSorter<DefaultTableModel> sorter = new TableRowSorter<>(rows);
    private List<InteractionStore.Entry> visible = List.of();
    final SessionController controller;
    private final ExecutorService files = Executors.newSingleThreadExecutor(r -> SessionController.daemon(r, "interactsh-bridge-files"));
    private boolean connecting;
    private boolean disposed;
    private final JTabbedPane tabs = new JTabbedPane();
    private JPanel header, toolbar, callback, filters;

    BridgePanel(MontoyaApi api) {
        super(new BorderLayout()); this.api = api;
        controller = new SessionController(SwingUtilities::invokeLater, new SessionController.Listener() {
            public void connected(Session s, Poll first) { connecting = false; address.setText(s.address()); accept(s, first); tabs.setSelectedIndex(0); state(); }
            public void polled(Poll result) { Session active = controller.session(); if (active != null) accept(active, result); }
            public void error(String message) { connecting = false; status.setText(message); status.setToolTipText(message); state(); }
        });
        server.setEditable(false); address.setEditable(false); address.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 14));
        search.putClientProperty("JTextField.placeholderText", "Search interactions");
        load();
        mode.addActionListener(e -> { boolean custom = mode.getSelectedIndex() == 1; server.setEditable(custom); token.setEnabled(custom);
            if (!custom) { if (!PUBLIC.contains(String.valueOf(server.getSelectedItem()))) server.setSelectedIndex(0); token.setText(""); } });
        JPanel results = new JPanel(new BorderLayout(0, 16)); results.setBorder(BorderFactory.createEmptyBorder(18, 22, 18, 22));
        header = new JPanel(new BorderLayout());
        JLabel title = new JLabel("Interactsh Bridge"); title.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 23));
        JPanel heading = new JPanel(new GridLayout(2, 1, 0, 5)); heading.setOpaque(false); heading.add(title);
        JLabel subtitle = new JLabel("Your Interactsh sessions, inside Burp Suite."); subtitle.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 13)); heading.add(subtitle); header.add(heading);
        toolbar = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0)); toolbar.add(poll); toolbar.add(disconnect); header.add(toolbar, BorderLayout.EAST);
        callback = new JPanel(new BorderLayout(12, 8)); callback.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(new Color(0xDDE2E8)), BorderFactory.createEmptyBorder(14, 16, 14, 16)));
        callback.add(new JLabel("CALLBACK ADDRESS"), BorderLayout.NORTH); callback.add(address);
        JPanel addressActions = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0)); addressActions.setOpaque(false); addressActions.add(generate); addressActions.add(copy); callback.add(addressActions, BorderLayout.EAST);
        filters = new JPanel(new BorderLayout(12, 0));
        JPanel searchBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0)); searchBar.setOpaque(false); searchBar.add(protocol); searchBar.add(new JLabel("Search")); searchBar.add(search); filters.add(searchBar);
        count.setBorder(BorderFactory.createEmptyBorder(0, 12, 0, 0)); filters.add(count, BorderLayout.EAST);
        JPanel top = new JPanel(new BorderLayout(0, 18)); top.setOpaque(false); top.add(header, BorderLayout.NORTH); top.add(callback); top.add(filters, BorderLayout.SOUTH); results.add(top, BorderLayout.NORTH);
        table.setRowHeight(31); table.setShowGrid(false); table.setIntercellSpacing(new Dimension(0, 0)); table.setFillsViewportHeight(true); table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION); table.setRowSorter(sorter);
        DefaultTableCellRenderer renderer = new DefaultTableCellRenderer(); renderer.putClientProperty("html.disable", true); table.setDefaultRenderer(Object.class, renderer);
        table.getSelectionModel().addListSelectionListener(e -> { if (!e.getValueIsAdjusting()) showSelected(); });
        for (Object[] tab : new Object[][]{{"Request", request}, {"Response", response}, {"Details", details}, {"Raw JSON", raw}, {"Notes", notes}}) {
            JPanel p = new JPanel(new BorderLayout()); JTextArea text = (JTextArea) tab[1]; p.add(new JScrollPane(text));
            if (text != notes) { JButton cp = button("Copy " + tab[0]); cp.addActionListener(e -> copyText(text.getText())); JPanel foot = new JPanel(new FlowLayout(FlowLayout.RIGHT)); foot.add(cp); p.add(foot, BorderLayout.SOUTH); }
            detailTabs.addTab((String) tab[0], p);
        }
        notes.setEditable(true); notes.setText(""); notes.setToolTipText("Add notes for this workspace. Notes are included in interaction exports.");
        int[] widths = {85, 200, 150, 360, 220};
        for (int i = 0; i < widths.length; i++) table.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);
        JScrollPane tableScroll = new JScrollPane(table); tableScroll.setColumnHeaderView(table.getTableHeader());
        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, detailTabs); split.setResizeWeight(.45); split.setBorder(BorderFactory.createEmptyBorder()); split.setDividerLocation(280); results.add(split);
        JPanel foot = new JPanel(new BorderLayout()); foot.setOpaque(false);
        JPanel information = new JPanel(new GridLayout(2, 1, 0, 4)); information.setOpaque(false); information.add(status); information.add(lastPoll); foot.add(information);
        JPanel actions = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0)); actions.setOpaque(false);
        JButton export = button("Export interactions…"), clear = button("Clear view"); actions.add(clear); actions.add(export); foot.add(actions, BorderLayout.EAST); results.add(foot, BorderLayout.SOUTH);
        tabs.addTab("Interactions", results); tabs.addTab("Connection", connectionPanel()); add(tabs);
        tabs.setSelectedIndex(1);
        connect.addActionListener(e -> connect(null)); disconnect.addActionListener(e -> { controller.disconnect(true); connecting = false; address.setText(""); status.setText("Disconnected · Captured interactions remain available"); state(); });
        poll.addActionListener(e -> { status.setText("Polling…"); controller.pollNow(); }); generate.addActionListener(e -> { Session s = controller.session(); if (s != null) address.setText(s.address()); });
        copy.addActionListener(e -> copyText(address.getText()));
        protocol.addActionListener(e -> filter()); search.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { filter(); } public void removeUpdate(DocumentEvent e) { filter(); } public void changedUpdate(DocumentEvent e) { filter(); }
        });
        clear.addActionListener(e -> { if (JOptionPane.showConfirmDialog(this, "Clear captured interactions from this view? Export them first to keep a copy.", "Clear interactions", JOptionPane.OK_CANCEL_OPTION) == JOptionPane.OK_OPTION) { store.clear(); refresh(); } });
        export.addActionListener(e -> export()); saveSession.addActionListener(e -> saveSession()); resume.addActionListener(e -> resume());
        state(); clearDetails();
    }
    private static JSpinner number(int value, int min, int max) { return new JSpinner(new SpinnerNumberModel(value, min, max, 1)); }
    private static JButton button(String text) { JButton b = new JButton(text); b.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 12)); b.setMargin(new Insets(8, 13, 8, 13)); return b; }
    private static JTextArea area() { JTextArea t = new JTextArea(); t.setEditable(false); t.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 13)); t.setLineWrap(true); t.setWrapStyleWord(false); t.setMargin(new Insets(14, 14, 14, 14)); return t; }
    private JPanel connectionPanel() {
        JPanel panel = new JPanel(new GridBagLayout()); GridBagConstraints c = new GridBagConstraints(); c.anchor = GridBagConstraints.WEST; c.insets = new Insets(9, 10, 9, 10);
        Object[][] fields = {{"Server type", mode}, {"Server URL", server}, {"Authentication token", token}, {"Correlation ID length", idLength}, {"Nonce length", nonceLength}, {"Poll interval (seconds)", interval}, {"Network timeout (seconds)", timeout}};
        for (int i = 0; i < fields.length; i++) { c.gridy = i; c.gridx = 0; panel.add(new JLabel((String) fields[i][0]), c); c.gridx = 1; panel.add((Component) fields[i][1], c); }
        c.gridy++; c.gridx = 0; c.gridwidth = 2; panel.add(new JLabel("ID lengths must match your server. Public servers normally use 20 + 13."), c);
        c.gridy++; panel.add(new JLabel("TLS certificates are verified. Tokens and keys stay in memory unless you save an encrypted session."), c);
        c.gridy++; JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0)); buttons.add(connect); buttons.add(resume); buttons.add(saveSession); panel.add(buttons, c);
        c.gridy++; JLabel connectionStatus = new JLabel(status.getText()); connectionStatus.setPreferredSize(new Dimension(680, 45));
        status.addPropertyChangeListener("text", e -> { connectionStatus.setText(status.getText()); connectionStatus.setToolTipText(status.getText()); }); panel.add(connectionStatus, c);
        return panel;
    }
    private Config config() { return new Config(String.valueOf(server.isEditable() ? server.getEditor().getItem() : server.getSelectedItem()), mode.getSelectedIndex() == 0 ? "" : new String(token.getPassword()), (int) idLength.getValue(), (int) nonceLength.getValue(), (int) interval.getValue(), (int) timeout.getValue()); }
    private void connect(Session restored) {
        try {
            Config config = restored == null ? config() : restored.config();
            if (restored != null) setConfig(config);
            savePreferences(config); connecting = true; status.setText(restored == null ? "Generating keys and registering…" : "Validating restored session…"); state();
            controller.connect(config, restored);
        } catch (Exception ex) { connecting = false; error(ex); state(); }
    }
    private void setConfig(Config c) { mode.setSelectedIndex(PUBLIC.contains(c.url()) ? 0 : 1); server.setEditable(mode.getSelectedIndex() == 1); server.setSelectedItem(c.url()); token.setText(c.token()); idLength.setValue(c.idLength()); nonceLength.setValue(c.nonceLength()); interval.setValue(c.interval()); timeout.setValue(c.timeout()); }
    private void load() {
        try { String saved = api.persistence().preferences().getString("interactsh-bridge.config"); if (saved != null) setConfig(JSON.fromJson(saved, Config.class)); }
        catch (Exception ex) { status.setText("Saved configuration could not be loaded. Check connection settings."); }
    }
    private void savePreferences(Config c) { api.persistence().preferences().setString("interactsh-bridge.config", JSON.toJson(new Config(c.url(), "", c.idLength(), c.nonceLength(), c.interval(), c.timeout()))); }
    private void accept(Session s, Poll data) {
        int added = store.add(s, data); refresh();
        status.setText("Connected to " + java.net.URI.create(s.config().url()).getHost() + " · " + added + " new" + (data.rejected() == 0 ? "" : " · " + data.rejected() + " unreadable record(s)"));
        lastPoll.setText("Last successful poll: " + java.time.LocalTime.now().withNano(0));
    }
    private void state() {
        boolean active = controller.session() != null;
        connect.setEnabled(!active && !connecting); resume.setEnabled(!active && !connecting); disconnect.setEnabled(active || connecting);
        poll.setEnabled(active); generate.setEnabled(active); copy.setEnabled(active); saveSession.setEnabled(active);
        for (Component c : new Component[]{mode, server, idLength, nonceLength, interval, timeout}) c.setEnabled(!active && !connecting);
        token.setEnabled(!active && !connecting && mode.getSelectedIndex() == 1);
        if (connecting) tabs.setSelectedIndex(0);
    }
    void refresh() {
        InteractionStore.Entry selected = selected(); visible = store.values(); rows.setRowCount(0);
        for (InteractionStore.Entry entry : visible) { JsonObject d = entry.data(); rows.addRow(new Object[]{text(d, "protocol").toUpperCase(Locale.ROOT), text(d, "timestamp"), text(d, "remote-address"), text(d, "full-id").isEmpty() ? text(d, "unique-id") : text(d, "full-id"), entry.server()}); }
        count.setText(visible.size() + " interactions" + (store.evicted == 0 ? "" : " · " + store.evicted + " evicted")); filter();
        if (selected != null) { int idx = visible.indexOf(selected); if (idx >= 0) { int v = table.convertRowIndexToView(idx); if (v >= 0) table.setRowSelectionInterval(v, v); } }
        if (table.getSelectedRow() < 0) clearDetails();
    }
    private InteractionStore.Entry selected() { int index = table.getSelectedRow(); if (index < 0) return null; int model = table.convertRowIndexToModel(index); return model >= visible.size() ? null : visible.get(model); }
    private void filter() {
        String query = search.getText().toLowerCase(Locale.ROOT), selected = String.valueOf(protocol.getSelectedItem()).toLowerCase(Locale.ROOT);
        sorter.setRowFilter(new RowFilter<>() { public boolean include(Entry<? extends DefaultTableModel, ? extends Integer> row) {
            if (row.getIdentifier() >= visible.size()) return false;
            InteractionStore.Entry record = visible.get(row.getIdentifier()); String p = text(record.data(), "protocol").toLowerCase(Locale.ROOT).replace("https", "http").replace("smtps", "smtp");
            boolean matches = selected.equals("all protocols") || p.equals(selected) || selected.equals("other") && !Set.of("dns", "http", "smtp", "ldap", "ftp", "smb").contains(p);
            return matches && (record.data().toString() + record.server()).toLowerCase(Locale.ROOT).contains(query);
        }});
    }
    private void clearDetails() { request.setText("Select an interaction to inspect its request."); response.setText(""); details.setText(""); raw.setText(""); }
    private void showSelected() {
        InteractionStore.Entry entry = selected(); if (entry == null) { clearDetails(); return; }
        JsonObject d = entry.data(); request.setText(text(d, "raw-request")); response.setText(text(d, "raw-response")); raw.setText(JSON.toJson(d));
        StringBuilder summary = new StringBuilder("Server: " + entry.server() + "\nSession: " + entry.sessionId() + "\n\n");
        for (String field : List.of("protocol", "unique-id", "full-id", "remote-address", "timestamp", "q-type")) summary.append(field).append(": ").append(text(d, field)).append('\n');
        details.setText(summary.toString()); for (JTextArea t : List.of(request, response, details, raw)) t.setCaretPosition(0);
    }
    private void copyText(String text) { try { Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text), null); status.setText("Copied to clipboard"); } catch (Exception ex) { status.setText("Clipboard unavailable"); } }
    private Path chooseSave(String name) {
        JFileChooser picker = new JFileChooser(); picker.setSelectedFile(new java.io.File(name)); if (picker.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return null;
        Path path = picker.getSelectedFile().toPath(); if (Files.exists(path) && JOptionPane.showConfirmDialog(this, "Replace this file?", "Save", JOptionPane.OK_CANCEL_OPTION) != JOptionPane.OK_OPTION) return null; return path;
    }
    private void export() {
        Path path = chooseSave("interactsh-bridge-interactions.json"); if (path == null) return;
        String content = JSON.toJson(store.export(notes.getText())); files.execute(() -> { try { Files.writeString(path, content); ui(() -> status.setText("Interactions exported")); } catch (Exception ex) { ui(() -> error(ex)); } });
    }
    private char[] password(String title) { JPasswordField field = new JPasswordField(24); if (JOptionPane.showConfirmDialog(this, field, title, JOptionPane.OK_CANCEL_OPTION) != JOptionPane.OK_OPTION) return null; return field.getPassword(); }
    private void saveSession() {
        Session s = controller.session(); if (s == null) return;
        Path path = chooseSave("interactsh-bridge-session.ibs"); if (path == null) return;
        char[] pass = password("Session password (at least 12 characters)"); if (pass == null) return;
        files.execute(() -> { try { Files.write(path, SessionFile.encode(s, pass)); ui(() -> status.setText("Encrypted session saved; interactions are exported separately")); }
            catch (Exception ex) { ui(() -> error(ex)); } finally { Arrays.fill(pass, '\0'); } });
    }
    private void resume() {
        JFileChooser picker = new JFileChooser(); if (picker.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) return;
        Path path = picker.getSelectedFile().toPath(); char[] pass = password("Session password"); if (pass == null) return;
        resume.setEnabled(false); connect.setEnabled(false);
        files.execute(() -> { try {
            if (Files.size(path) > 65536) throw new java.io.IOException("Session file exceeds 64 KiB.");
            Session s = SessionFile.decode(Files.readAllBytes(path), pass); ui(() -> { if (controller.session() == null && !connecting) connect(s); });
        } catch (Exception ex) { ui(() -> { error(ex); state(); }); } finally { Arrays.fill(pass, '\0'); } });
    }
    private void ui(Runnable task) { SwingUtilities.invokeLater(() -> { if (!disposed) task.run(); }); }
    private void error(Exception ex) { status.setText(SessionController.safe(ex)); status.setToolTipText(status.getText()); api.logging().logToError("Interactsh Bridge: " + ex.getClass().getSimpleName()); }
    void shutdown() { disposed = true; controller.close(); files.shutdownNow(); token.setText(""); }
}
