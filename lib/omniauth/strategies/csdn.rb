require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class Csdn < OmniAuth::Strategies::OAuth2
      option :client_options, {
          :site => 'http://api.csdn.net',
          :authorize_url => '/oauth2/authorize',
          :token_url => '/oauth2/access_token',
      }

      def request_phase
        super
      end

      def authorize_params
        super.tap do |params|
          %w[scope client_options].each do |v|
            if request.params[v]
              params[v.to_sym] = request.params[v]
              # to support omniauth-oauth2's auto csrf protection
              session['omniauth.state'] = params[:state] if v == 'state'
            end
          end
        end
      end

      uid { raw_info['username'].to_s }

      info do
        {
            'name' => raw_info['nickname'],
            'username' => raw_info['username'],
            'email' => @email['email']
        }
      end

      extra do
        {:raw_info => raw_info}
      end

      def raw_info
        access_token.options[:param_name] = 'access_token'
        access_token.options[:mode] = :query
        @email ||= access_token.get('/user/getemail').parsed
        @raw_info ||= access_token.get('/user/getinfo').parsed
        raise ::MultiJson::DecodeError unless @raw_info.is_a?(Hash)
        @raw_info
      end

    end
  end
end

OmniAuth.config.add_camelization 'csdn', 'Csdn'
