#!/bin/bash

# Start the Flask API server in the background on internal port 5000
python api/server.py &

# Start the Streamlit Dashboard on the Render-assigned PORT (bound to 0.0.0.0)
streamlit run dashboard/dashboard.py \
    --server.port $PORT \
    --server.address 0.0.0.0 \
    --server.headless true \
    --browser.gatherUsageStats false
