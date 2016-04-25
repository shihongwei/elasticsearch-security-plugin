package org.tamal.es;

import org.elasticsearch.http.HttpServerModule;
import org.elasticsearch.plugins.Plugin;
import org.elasticsearch.transport.TransportModule;

/**
 * This is the starting point of the plugin.
 * @author Tamal Kanti Nath
 */
public class SecurityPlugin extends Plugin {

	/**
	 * The plugin name.
	 */
	public static final String NAME = "Elasticsearch Security Plugin";

	@Override
	public String name() {
		return NAME;
	}

	@Override
	public String description() {
		return "This plugin provides authentication and authorization for elasticsearch.";
	}

    /**
     * Overrides the default HttpServerTransport.
     * @param module the {@link HttpServerModule} to set
     */
    public void onModule(HttpServerModule module) {
        module.setHttpServerTransport(SecuredHttp.class, name());
    }

	/**
	 * Overrides the default TransportModule.
	 * @param module the {@link TransportModule} to set
	 */
	public void onModule(TransportModule module) {
		module.setTransport(SecuredTransport.class, name());
	}
}
