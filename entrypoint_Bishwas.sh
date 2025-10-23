#!/bin/bash
echo "Starting Certifier setup..."

# Navigate and run the main shell script
cd /certifier-framework-for-confidential-computing
pwd

# Run your custom logic
./start_certifier_service.sh  

# Optional: Keep container alive
tail -f /dev/null
