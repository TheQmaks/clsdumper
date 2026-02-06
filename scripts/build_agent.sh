#!/bin/bash
# Build the TypeScript Frida agent into agent.js
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
AGENT_DIR="$PROJECT_DIR/agent"
OUTPUT="$PROJECT_DIR/clsdumper/frida/scripts/agent.js"

echo "Building Frida agent..."

cd "$AGENT_DIR"

# Install dependencies if needed
if [ ! -d "node_modules" ]; then
    echo "Installing dependencies..."
    npm install
fi

# Build with frida-compile
echo "Compiling TypeScript → agent.js..."
npm run build

if [ -f "$OUTPUT" ]; then
    SIZE=$(wc -c < "$OUTPUT")
    echo "Build successful: $OUTPUT ($SIZE bytes)"
else
    echo "ERROR: Build failed — $OUTPUT not created"
    exit 1
fi
