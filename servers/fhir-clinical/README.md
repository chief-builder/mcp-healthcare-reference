# fhir-clinical-mcp

MCP server for FHIR Clinical (curated MCP subset)

This is a Model Context Protocol (MCP) server for the FHIR Clinical (curated MCP subset) API, generated from an OpenAPI specification.

## Installation

```bash
npm install
npm run build
```

## Usage

### Environment Variables

- `API_KEY`: Your API key (optional if providing in requests)
- `PORT`: Port to run the server on (default: 8080)
- `TRANSPORT`: Transport method to use ('http' or 'stdio', default: 'http')

### Starting the Server

```bash
npm start
```

Or with environment variables:

```bash
API_KEY=your_api_key PORT=8080 npm start
```

### Using the CLI

```bash
# Install globally
npm install -g .

# Run the server
fhir-clinical-mcp --port=8080 --apiKey=your_api_key
```

## Available Tools

This MCP server exposes the following API endpoints as MCP tools:

- `getPatient`: Read a Patient by id
- `patientEverything`: Everything in a patient's compartment
- `searchObservation`: Search Observations
- `searchCondition`: Search Conditions
- `searchMedicationRequest`: Search MedicationRequests


## Authentication

The server supports authentication using API keys. You can authenticate requests in one of the following ways:

1. Pass the API key in the Authorization header:
 ```
 Authorization: Bearer your_api_key
 ```

2. Pass the API key in the request parameters:
 ```json
 {
   "jsonrpc": "2.0",
   "id": "1",
   "method": "tools.call",
   "params": {
     "tool": "someOperation",
     "parameters": {
       "apiKey": "your_api_key",
       // other parameters
     }
   }
 }
 ```

3. Use the default API key configured when starting the server.

## Example Requests

### List Available Tools

```json
{
"jsonrpc": "2.0",
"id": "1",
"method": "tools.list"
}
```

### Sample Tool Call

```json
{
"jsonrpc": "2.0",
"id": "2",
"method": "tools.call",
"params": {
  "tool": "getPatient",
  "parameters": {
    // Add parameters here based on the tool's requirements
  }
}
}
```

## License

MIT