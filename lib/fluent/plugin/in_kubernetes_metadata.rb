#
# Fluentd Kubernetes Metadata Filter Plugin - Enrich Fluentd events with
# Kubernetes metadata
#
# Copyright 2015 Red Hat, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
require 'fluent/input'


module Fluent
  class KubernetesMetadataInput < Fluent::Input
    K8_POD_CA_CERT = 'ca.crt'
    K8_POD_TOKEN = 'token'

    Fluent::Plugin.register_input('kubernetes_metadata', self)

    desc 'URL to the API server. Set this to retrieve further kubernetes metadata for logs from kubernetes API server'
    config_param :kubernetes_url, :string, default: nil
    desc 'k8s API version to use'
    config_param :apiVersion, :string, default: 'v1'
    desc 'path to a client cert file to authenticate to the API server'
    config_param :client_cert, :string, default: nil
    desc 'path to a client key file to authenticate to the API server'
    config_param :client_key, :string, default: nil
    desc 'path to CA file for Kubernetes server certificate validation'
    config_param :ca_file, :string, default: nil
    desc 'validate SSL certificates'
    config_param :verify_ssl, :bool, default: true
    desc 'path to a file containing the bearer token to use for authentication'
    config_param :bearer_token_file, :string, default: nil
    config_param :secret_dir, :string, default: '/var/run/secrets/kubernetes.io/serviceaccount'
    desc 'Kubernetes resource type to watch.'
    config_param :resource, :string, default: "Events"

    def syms_to_strs(hsh)
      newhsh = {}
      hsh.each_pair do |kk,vv|
        if vv.is_a?(Hash)
          vv = syms_to_strs(vv)
        end
        if kk.is_a?(Symbol)
          newhsh[kk.to_s] = vv
        else
          newhsh[kk] = vv
        end
      end
      newhsh
    end

    def initialize
      super
      require 'kubeclient'
      require 'active_support/core_ext/object/blank'
    end

    def configure(conf)
      super

      # Use Kubernetes default service account if we're in a pod.
      if @kubernetes_url.nil?
        env_host = ENV['KUBERNETES_SERVICE_HOST']
        env_port = ENV['KUBERNETES_SERVICE_PORT']
        if env_host.present? && env_port.present?
          @kubernetes_url = "https://#{env_host}:#{env_port}/api"
        end
      end
      unless @kubernetes_url
        raise Fluent::ConfigError, "kubernetes_url is not defined"
      end

      # Use SSL certificate and bearer token from Kubernetes service account.
      if Dir.exist?(@secret_dir)
        ca_cert = File.join(@secret_dir, K8_POD_CA_CERT)
        pod_token = File.join(@secret_dir, K8_POD_TOKEN)

        if !@ca_file.present? and File.exist?(ca_cert)
          @ca_file = ca_cert
        end

        if !@bearer_token_file.present? and File.exist?(pod_token)
          @bearer_token_file = pod_token
        end
      end
    end

    def start

      start_kubclient

      @thread = Thread.new(&method(:watch_resource))
      @thread.abort_on_exception = true

    end

    def start_kubclient
      return @client if @client

      if @kubernetes_url.present?

        ssl_options = {
            client_cert: @client_cert.present? ? OpenSSL::X509::Certificate.new(File.read(@client_cert)) : nil,
            client_key:  @client_key.present? ? OpenSSL::PKey::RSA.new(File.read(@client_key)) : nil,
            ca_file:     @ca_file,
            verify_ssl:  @verify_ssl ? OpenSSL::SSL::VERIFY_PEER : OpenSSL::SSL::VERIFY_NONE
        }

        auth_options = {}

        if @bearer_token_file.present?
          bearer_token = File.read(@bearer_token_file)
          auth_options[:bearer_token] = bearer_token
        end

        @client = Kubeclient::Client.new @kubernetes_url, @apiVersion,
                                         ssl_options: ssl_options,
                                         auth_options: auth_options

        begin
          @client.api_valid?
        rescue KubeException => kube_error
          raise Fluent::ConfigError, "Invalid Kubernetes API #{@apiVersion} endpoint #{@kubernetes_url}: #{kube_error.message}"
        end
      end
    end

    def shutdown
      @thread.exit
    end

    def watch_resource
      begin
        resource_version = @client.get_pods.resourceVersion
        watcher          = @client.watch_entities(@resource, options = {resource_version: resource_version})
      rescue Exception => e
        raise Fluent::ConfigError, "Exception encountered fetching metadata from Kubernetes API endpoint: #{e.message}"
      end


      watcher.each do |notice|
        time = Engine.now
        emit_event(notice.object, time, notice.type)
      end
    end

    def emit_event(event_obj, time, type)
      payload = syms_to_strs(event_obj)
      payload['event_type'] = type
      res_name = @resource.to_s.downcase
      namespace_name = event_obj['metadata']['namespace'] ? event_obj['metadata']['namespace'] : "openshift-infra"
      if event_obj['metadata']['labels'] then
        labels = []
        syms_to_strs(event_obj['metadata']['labels'].to_h).each{|k,v| labels << "#{k}=#{v}"}
        payload['metadata']['labels'] = labels
      end
      if event_obj['metadata']['annotations'] then
        annotations = []
        syms_to_strs(event_obj['metadata']['annotations'].to_h).each{|k,v| annotations << "#{k}=#{v}"}
        payload['metadata']['annotations'] = annotations
      end

      tag = "kubernetes.#{res_name}.#{namespace_name}.#{event_obj['metadata']['name']}"

      router.emit(tag, time, payload)
    end

  end
end
