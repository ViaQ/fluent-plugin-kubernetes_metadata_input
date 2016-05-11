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

    config_param :kubernetes_url, :string, default: nil
    config_param :apiVersion, :string, default: 'v1'
    config_param :client_cert, :string, default: nil
    config_param :client_key, :string, default: nil
    config_param :ca_file, :string, default: nil
    config_param :verify_ssl, :bool, default: true
    config_param :bearer_token_file, :string, default: nil
    config_param :merge_json_log, :bool, default: true
    config_param :preserve_json_log, :bool, default: true
    config_param :include_namespace_id, :bool, default: false
    config_param :secret_dir, :string, default: '/var/run/secrets/kubernetes.io/serviceaccount'
    config_param :de_dot, :bool, default: true
    config_param :de_dot_separator, :string, default: '_'
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

    def get_immutable_metadata(pod_name, namespace_name)
      begin
        metadata = @client.get_pod(pod_name, namespace_name)
        return if !metadata
        pod_immutable = {
          'name' => metadata['metadata']['name'],
          'namespace_name'=> metadata['metadata']['namespace'],
          'id' => metadata['metadata']['uid'],
          'creationTimestamp' => metadata['metadata']['creationTimestamp']
        }
        return pod_immutable
      rescue KubeException => e
        raise Fluent::ConfigError, "Exception encountered fetching Kubernetes pod immutable metadata: #{e.message}"
      end
    end

    def initialize
      super
      require 'kubeclient'
      require 'active_support/core_ext/object/blank'
    end

    def configure(conf)
      super


      if @de_dot && (@de_dot_separator =~ /\./).present?
        raise Fluent::ConfigError, "Invalid de_dot_separator: cannot be or contain '.'"
      end

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

      if @refresh_pods_on_start
        pod_refresh = Thread.new(&method(:refresh_pods))
        pod_refresh.join
      end

#      if @watch
#        @thread = Thread.new(&method(:watch_pods))
#        @thread.abort_on_exception = true
#      end

      @thread = Thread.new(&method(:watch_resource))
      @thread.abort_on_exception = true

      @threads = []

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
      @thread_events.exit
    end



    def merge_json_log(record)
      if record.has_key?('log')
        log = record['log'].strip
        if log[0].eql?('{') && log[-1].eql?('}')
          begin
            record = JSON.parse(log).merge(record)
            unless @preserve_json_log
              record.delete('log')
            end
          rescue JSON::ParserError
          end
        end
      end
      record
    end

    def de_dot!(h)
      h.keys.each do |ref|
        if h[ref] && ref =~ /\./
          v = h.delete(ref)
          newref = ref.to_s.gsub('.', @de_dot_separator)
          h[newref] = v
        end
      end
    end

    def watch_pods
      begin
        resource_version = @client.get_pods.resourceVersion
        watcher          = @client.watch_pods(resource_version)
      rescue Exception => e
        raise Fluent::ConfigError, "Exception encountered fetching metadata from Kubernetes API endpoint: #{e.message}"
      end


      watcher.each do |notice|
        time = Engine.now
        case notice.type
          when 'ADDED'
            emit_pod_added(notice.object['metadata']['name'],notice.object['metadata']['namespace'], time)
            emit_pod_config_update(notice.object,time)
          when 'MODIFIED'
            emit_pod_config_update(notice.object,time)
          else
            emit_pod_config_update(notice.object,time)
            # Don't pay attention to creations, since the created pod may not
            # end up on this node.
        end
      end
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
#      payload['annotations'] = syms_to_strs(notice_obj['metadata']['annotations'].to_h).map{|k,v| "#{k}=#{v}"}.join(',') if notice_obj['metadata']['annotations']
      if event_obj['metadata']['annotations'] then
        annotations = []
        syms_to_strs(event_obj['metadata']['annotations'].to_h).each{|k,v| annotations << "#{k}=#{v}"}
        payload['metadata']['annotations'] = annotations
      end

      tag = "kubernetes.#{res_name}.#{namespace_name}.#{event_obj['metadata']['name']}"

      router.emit(tag, time, payload)
    end

    def emit_pod_added(pod_name, namespace_name, time)
      payload = get_immutable_metadata(pod_name, namespace_name)
      tag = "kubernetes.pod.#{namespace_name}.#{pod_name}"
      router.emit(tag, time, payload)
    end

    def emit_pod_config_update(notice_obj, time)
      namespace_name = notice_obj['metadata']['namespace']
      tag = "kubernetes.pod_update.#{notice_obj['metadata']['namespace']}.#{notice_obj['metadata']['name']}"
      payload = {
        'name' => notice_obj['metadata']['name'],
        'namespace_name' => notice_obj['metadata']['namespace'],
        'status' => notice_obj['status']['phase'],
        'containers' => notice_obj['status']['containerStatuses']
      }
      payload['labels'] = syms_to_strs(notice_obj['metadata']['labels'].to_h).map{|k,v| "{#{k}=#{v}}"}.join(',') if notice_obj['metadata']['labels']
      payload['annotations'] = syms_to_strs(notice_obj['metadata']['annotations'].to_h).map{|k,v| "#{k}=#{v}"}.join(',') if notice_obj['metadata']['annotations']
      payload['pod_ip'] = notice_obj['status']['podIP'] if notice_obj['status']['podIP']
      payload['host_ip'] = notice_obj['status']['hostIP'] if notice_obj['status']['hostIP']
      payload['hostname'] = notice_obj['status']['host'] if notice_obj['status']['host']
      payload['containers'] = notice_obj['status']['containerStatuses'] if notice_obj['status']['containerStatuses']

      router.emit(tag, time, payload)
    end

    def refresh_pods
      @client.get_pods
    end

  end
end
