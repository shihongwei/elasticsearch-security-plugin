package org.tamal.es;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;

import org.elasticsearch.Version;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.io.stream.NamedWriteableRegistry;
import org.elasticsearch.common.network.NetworkService;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.BigArrays;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.netty.NettyTransport;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.ChannelPipeline;
import org.jboss.netty.channel.ChannelPipelineFactory;
import org.jboss.netty.channel.ChannelStateEvent;
import org.jboss.netty.channel.SimpleChannelHandler;
import org.jboss.netty.handler.ssl.SslHandler;

/**
 * @author Tamal Kanti Nath
 */
public class SecuredTransport extends NettyTransport {

	SSLContext sslContext;

	/**
	 * Initialize the SecuredTransport.
	 * @param settings the {@link Settings} to set
	 * @param threadPool the {@link ThreadPool} to set
	 * @param networkService the {@link NetworkService} to set
	 * @param bigArrays the {@link BigArrays} to set
	 * @param version the {@link Version} to set
	 * @param namedWriteableRegistry the {@link NamedWriteableRegistry} to set
	 * @throws GeneralSecurityException if SSL Context cannot be created
	 * @throws IOException if keystore or the config file cannot be read
	 */
	@Inject
	public SecuredTransport(Settings settings, ThreadPool threadPool, NetworkService networkService,
			BigArrays bigArrays, Version version, NamedWriteableRegistry namedWriteableRegistry)
			throws IOException, GeneralSecurityException {
		super(settings, threadPool, networkService, bigArrays, version, namedWriteableRegistry);
		sslContext = SSLEngineFactory.createSSLContext();
	}

	@Override
	public ChannelPipelineFactory configureClientChannelPipelineFactory() {
		return new SslClientChannelPipelineFactory(this);
	}

	@Override
	public ChannelPipelineFactory configureServerChannelPipelineFactory(String name, Settings profileSettings) {
		return new SslServerChannelPipelineFactory(this, name, this.settings, profileSettings);
	}

	private class SslClientChannelPipelineFactory extends NettyTransport.ClientChannelPipelineFactory {

		public SslClientChannelPipelineFactory(NettyTransport nettyTransport) {
			super(nettyTransport);
		}

		@Override
		public ChannelPipeline getPipeline() throws Exception {
			ChannelPipeline pipeline = super.getPipeline();
			pipeline.addFirst("sslInitializer", new ClientSslHandlerInitializer());
			return pipeline;
		}

		private class ClientSslHandlerInitializer extends SimpleChannelHandler {

			public ClientSslHandlerInitializer() {
				// Empty
			}

			@Override
			public void connectRequested(ChannelHandlerContext ctx, ChannelStateEvent e) {
				InetSocketAddress inet = (InetSocketAddress) e.getValue();
	            SSLEngine sslEngine = sslContext.createSSLEngine(inet.getHostName(), inet.getPort());
	            SSLParameters parameters = new SSLParameters();
	            parameters.setEndpointIdentificationAlgorithm("HTTPS");
	            sslEngine.setSSLParameters(parameters);
	            sslEngine.setUseClientMode(true);
	            ctx.getPipeline().replace(this, "ssl", new SslHandler(sslEngine));
	            ctx.getPipeline().addAfter("ssl", "handshake", new HandshakeWaitingHandler());
	            ctx.sendDownstream(e);
			}
		}

		private class HandshakeWaitingHandler extends SimpleChannelHandler {

			public HandshakeWaitingHandler() {
				// Empty
			}

			@Override
			public void channelConnected(final ChannelHandlerContext ctx, final ChannelStateEvent e) throws Exception {
				SslHandler sslHandler = ctx.getPipeline().get(SslHandler.class);
				sslHandler.handshake().addListener(future -> {
					if (future.isSuccess()) {
						ctx.getPipeline().remove(HandshakeWaitingHandler.class);
						ctx.sendUpstream(e);
					} else {
						future.getChannel().close();
					}
				});
			}
		}
	}

	private static class SslServerChannelPipelineFactory extends NettyTransport.ServerChannelPipelineFactory {

		private Settings profileSettings;
		private SSLContext sslContext;

		public SslServerChannelPipelineFactory(SecuredTransport transport, String name, Settings settings, Settings profileSettings) {
			super(transport, name, settings);
			this.profileSettings = profileSettings;
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
