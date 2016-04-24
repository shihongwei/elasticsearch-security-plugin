package org.tamal.es;

import java.io.IOException;
import java.security.GeneralSecurityException;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;

import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.network.NetworkService;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.BigArrays;
import org.elasticsearch.http.HttpChannel;
import org.elasticsearch.http.HttpRequest;
import org.elasticsearch.http.netty.NettyHttpServerTransport;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.ChannelPipeline;
import org.jboss.netty.channel.ChannelPipelineFactory;
import org.jboss.netty.channel.ExceptionEvent;
import org.jboss.netty.handler.ssl.SslHandler;

/**
 * @author Tamal Kanti Nath
 */
public class SecuredHttpServerTransport extends NettyHttpServerTransport {

	SSLContext sslContext;

	/**
	 * Initialize the SecuredHttpServerTransport.
	 * @param settings the {@link Settings} to set
	 * @param networkService the {@link NetworkService} to set
	 * @param bigArrays the {@link BigArrays} to set
	 * @throws GeneralSecurityException if SSL Context cannot be created
	 * @throws IOException if keystore or the config file cannot be read
	 */
	@Inject
	public SecuredHttpServerTransport(Settings settings, NetworkService networkService, BigArrays bigArrays) throws IOException, GeneralSecurityException {
		super(settings, networkService, bigArrays);
		sslContext = SSLEngineFactory.createSSLContext();
	}

	@Override
    protected void dispatchRequest(HttpRequest request, HttpChannel channel) {
    	super.dispatchRequest(request, channel);
    }

	@Override
	public ChannelPipelineFactory configureServerChannelPipelineFactory() {
    	if (sslContext == null) {
    		return super.configureServerChannelPipelineFactory();
    	}
        return new HttpsChannelPipelineFactory(this, detailedErrorsEnabled);
    }

    private static class HttpsChannelPipelineFactory extends NettyHttpServerTransport.HttpChannelPipelineFactory {

    	private SSLContext sslContext;

    	public HttpsChannelPipelineFactory(SecuredHttpServerTransport transport, boolean detailedErrorsEnabled) {
            super(transport, detailedErrorsEnabled);
            this.sslContext = transport.sslContext;
        }

        @Override
        public ChannelPipeline getPipeline() throws Exception {
            ChannelPipeline pipeline = super.getPipeline();
            SSLEngine sslEngine = sslContext.createSSLEngine(null, -1);
            sslEngine.setNeedClientAuth(false);
            sslEngine.setUseClientMode(false);
            pipeline.addFirst("ssl", new SslHandler(sslEngine));
            return pipeline;
        }

    }

}
