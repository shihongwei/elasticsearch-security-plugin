package org.tamal.es;

import org.elasticsearch.Version;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.io.stream.NamedWriteableRegistry;
import org.elasticsearch.common.network.NetworkService;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.BigArrays;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.netty.NettyTransport;
import org.jboss.netty.channel.ChannelPipelineFactory;

/**
 * @author Tamal Kanti Nath
 */
public class SecuredTransport extends NettyTransport {

	/**
	 * Initialize the SecuredTransport.
	 * @param settings the {@link Settings} to set
	 * @param threadPool the {@link ThreadPool} to set
	 * @param networkService the {@link NetworkService} to set
	 * @param bigArrays the {@link BigArrays} to set
	 * @param version the {@link Version} to set
	 * @param namedWriteableRegistry the {@link NamedWriteableRegistry} to set
	 */
	@Inject
	public SecuredTransport(Settings settings, ThreadPool threadPool, NetworkService networkService,
			BigArrays bigArrays, Version version, NamedWriteableRegistry namedWriteableRegistry) {
		super(settings, threadPool, networkService, bigArrays, version, namedWriteableRegistry);
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

	}

	private class SslServerChannelPipelineFactory extends NettyTransport.ServerChannelPipelineFactory {

		private Settings profileSettings;

		public SslServerChannelPipelineFactory(NettyTransport nettyTransport, String name, Settings settings, Settings profileSettings) {
			super(nettyTransport, name, settings);
			this.profileSettings = profileSettings;
		}
	}
		  
}
