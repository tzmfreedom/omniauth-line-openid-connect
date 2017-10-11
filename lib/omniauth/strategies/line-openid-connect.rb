require 'omniauth_openid_connect'

module OmniAuth
  module Strategies
    class LineOpenidConnect < ::OmniAuth::Strategies::OpenIDConnect

      args [:client_id, :client_secret]

      option :name, :line
      option :scope, [:openid, :profile]
      option :response_type, :code
      option :client_id
      option :client_secret
      option :issuer, 'https://access.line.me'
      option :client_auth_method, :body
      option :client_signing_alg, :HS256
      option :client_options, {
          port: 443,
          scheme: 'https',
          host: 'access.line.me',
          identifier: nil,
          secret: nil,
          redirect_uri: nil,
          authorization_endpoint: '/oauth2/v2.1/authorize',
          token_endpoint: '/oauth2/v2.1/token',
          userinfo_endpoint: '/v2/profile'
      }

      uid { user_info.raw_attributes['userId'] }

      info do
        {
            name:        user_info.raw_attributes['displayName'],
            image:       user_info.raw_attributes['pictureUrl'],
            description: user_info.raw_attributes['statusMessage']
        }
      end

      def request_phase
        options[:client_options].merge!(identifier: options[:client_id],
                                       secret: options[:client_secret],
                                       redirect_uri: callback_url)
        super
      end

      def callback_phase
        options[:client_options].merge!(identifier: options[:client_id],
                                       secret: options[:client_secret],
                                       redirect_uri: callback_url,
                                       host: 'api.line.me')
        super
      end

      def callback_url
        full_host + script_name + callback_path
      end
    end
  end
end