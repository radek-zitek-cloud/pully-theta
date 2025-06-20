#!/bin/bash
# setup-observability.sh - Quick setup script for observability stack

set -e

echo "🚀 Setting up Self-Hosted Observability Stack..."

# Create directory structure
echo "📁 Creating directory structure..."
mkdir -p {loki,promtail,prometheus,grafana/{provisioning/datasources,dashboards},nginx,scripts}

# Create Loki config
echo "⚙️  Creating Loki configuration..."
cat > loki/config.yml << 'EOF'
auth_enabled: false

server:
  http_listen_port: 3100
  grpc_listen_port: 9096
  log_level: info

common:
  path_prefix: /loki
  storage:
    filesystem:
      chunks_directory: /loki/chunks
      rules_directory: /loki/rules
  replication_factor: 1
  ring:
    instance_addr: 127.0.0.1
    kvstore:
      store: inmemory

query_range:
  results_cache:
    cache:
      embedded_cache:
        enabled: true
        max_size_mb: 100

schema_config:
  configs:
    - from: 2020-10-24
      store: boltdb-shipper
      object_store: filesystem
      schema: v11
      index:
        prefix: index_
        period: 24h

limits_config:
  enforce_metric_name: false
  reject_old_samples: true
  reject_old_samples_max_age: 168h
  max_cache_freshness_per_query: 10m
  split_queries_by_interval: 15m
EOF

# Create Promtail config
echo "⚙️  Creating Promtail configuration..."
cat > promtail/config.yml << 'EOF'
server:
  http_listen_port: 9080
  grpc_listen_port: 0

positions:
  filename: /tmp/positions.yaml

clients:
  - url: http://loki:3100/loki/api/v1/push

scrape_configs:
  - job_name: docker
    static_configs:
      - targets:
          - localhost
        labels:
          job: docker
          __path__: /var/lib/docker/containers/*/*log
    pipeline_stages:
      - json:
          expressions:
            output: log
            stream: stream
            attrs:
      - json:
          expressions:
            tag:
          source: attrs
      - regex:
          expression: (?P<container_name>(?:[^|]*))\|
          source: tag
      - timestamp:
          format: RFC3339Nano
          source: time
      - labels:
          stream:
          container_name:
      - output:
          source: output

  - job_name: system
    static_configs:
      - targets:
          - localhost
        labels:
          job: varlogs
          __path__: /var/log/*log
EOF

# Create Prometheus config
echo "⚙️  Creating Prometheus configuration..."
cat > prometheus/prometheus.yml << 'EOF'
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  - job_name: 'node-exporter'
    static_configs:
      - targets: ['node_exporter:9100']
    scrape_interval: 30s

  - job_name: 'cadvisor'
    static_configs:
      - targets: ['cadvisor:8080']
    scrape_interval: 30s

  - job_name: 'loki'
    static_configs:
      - targets: ['loki:3100']

  - job_name: 'grafana'
    static_configs:
      - targets: ['grafana:3000']
EOF

# Create Grafana datasources
echo "⚙️  Creating Grafana datasources..."
cat > grafana/provisioning/datasources/datasources.yml << 'EOF'
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: false
    editable: true

  - name: Loki
    type: loki
    access: proxy
    url: http://loki:3100
    isDefault: true
    editable: true
    jsonData:
      maxLines: 1000
EOF

# Create nginx config with JSON logging
echo "⚙️  Creating Nginx configuration..."
cat > nginx/nginx.conf << 'EOF'
events {
    worker_connections 1024;
}

http {
    log_format json_combined escape=json
    '{'
        '"time_local":"$time_local",'
        '"remote_addr":"$remote_addr",'
        '"remote_user":"$remote_user",'
        '"request":"$request",'
        '"status": "$status",'
        '"body_bytes_sent":"$body_bytes_sent",'
        '"request_time":"$request_time",'
        '"http_referrer":"$http_referer",'
        '"http_user_agent":"$http_user_agent"'
    '}';

    access_log /var/log/nginx/access.log json_combined;
    error_log /var/log/nginx/error.log warn;

    server {
        listen 80;
        server_name localhost;

        location / {
            root /usr/share/nginx/html;
            index index.html index.htm;
        }

        location /health {
            access_log off;
            return 200 "healthy\n";
            add_header Content-Type text/plain;
        }
    }
}
EOF

# Set proper permissions
echo "🔐 Setting permissions..."
chmod -R 755 grafana/
chmod -R 755 prometheus/
chmod -R 755 loki/
chmod -R 755 promtail/

echo "✅ Configuration files created successfully!"
echo ""
echo "🚀 To start the stack:"
echo "   docker-compose up -d"
echo ""
echo "📊 Access URLs:"
echo "   Grafana:    http://localhost:3000 (admin/admin123)"
echo "   Prometheus: http://localhost:9090"
echo "   Loki:       http://localhost:3100"
echo ""
echo "📝 Next steps:"
echo "   1. Start the stack: docker-compose up -d"
echo "   2. Wait for all services to be healthy"
echo "   3. Access Grafana and explore logs/metrics"
echo "   4. Generate some traffic: curl http://localhost:8081"
echo ""

# Create log generator script
echo "📝 Creating log generator script..."
cat > scripts/generate-logs.sh << 'EOF'
#!/bin/bash
# Generate sample logs for testing

echo "🔄 Generating sample logs..."

for i in {1..100}; do
    # Generate web traffic
    curl -s http://localhost:8081/ > /dev/null
    curl -s http://localhost:8081/health > /dev/null
    curl -s http://localhost:8081/nonexistent > /dev/null
    
    # Generate application logs
    echo "{\"level\":\"info\",\"msg\":\"Sample log message $i\",\"time\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"user_id\":\"user_$((i % 10))\"}" | docker exec -i example_app sh -c 'cat >> /var/log/app.log'
    
    sleep 1
done

echo "✅ Log generation complete!"
EOF

chmod +x scripts/generate-logs.sh

echo "🎉 Setup complete! Run 'docker-compose up -d' to start."