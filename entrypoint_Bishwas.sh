#!/bin/bash
echo "Starting Certifier setup..."

# Navigate and run the main shell script
cd /secure-federated-learning
pwd

# Run your custom logic
./start_certifier_service.sh  

# Optional: Keep container alive
tail -f /dev/null
