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
