package interactshbridge;

import burp.api.montoya.*;
import javax.swing.*;

public final class BridgeExtension implements BurpExtension {
    @Override public void initialize(MontoyaApi api) {
        api.extension().setName("Interactsh Bridge");
        Runnable setup = () -> {
            BridgePanel panel = new BridgePanel(api);
            api.userInterface().applyThemeToComponent(panel);
            api.userInterface().registerSuiteTab("Interactsh Bridge", panel);
            api.extension().registerUnloadingHandler(() -> {
                if (SwingUtilities.isEventDispatchThread()) panel.shutdown(); else SwingUtilities.invokeLater(panel::shutdown);
            });
            api.logging().logToOutput("Interactsh Bridge 1.0.0 loaded. Open Connection to choose a server. Based on Arken Collab's Interactsh workflow.");
        };
        try { if (SwingUtilities.isEventDispatchThread()) setup.run(); else SwingUtilities.invokeAndWait(setup); }
        catch (Exception ex) { throw new IllegalStateException("Interactsh Bridge initialization failed", ex); }
    }
}
