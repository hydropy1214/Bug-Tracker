export interface ImportedEndpoint {
  method: string;
  path: string;
  operationId: string | null;
  summary: string | null;
  parameters: unknown[];
  requestBody: unknown | null;
  security: unknown | null;
}

interface OpenApiDocument {
  openapi?: string;
  swagger?: string;
  servers?: Array<{ url?: string }>;
  basePath?: string;
  paths?: Record<string, Record<string, unknown>>;
}

const HTTP_METHODS = new Set(["get", "post", "put", "patch", "delete", "head", "options", "trace"]);

export function parseOpenApiJson(spec: unknown): {
  version: string;
  baseUrl: string | null;
  endpoints: ImportedEndpoint[];
} {
  let document: OpenApiDocument;
  if (typeof spec === "string") {
    try {
      document = JSON.parse(spec) as OpenApiDocument;
    } catch {
      throw new Error("Only JSON OpenAPI/Swagger documents are currently supported; YAML parsing is not installed");
    }
  } else if (spec && typeof spec === "object") {
    document = spec as OpenApiDocument;
  } else {
    throw new Error("spec must be an OpenAPI/Swagger JSON object or JSON string");
  }

  const version = document.openapi ?? document.swagger;
  if (!version || (!document.openapi && !document.swagger)) {
    throw new Error("Document is not recognised as OpenAPI 3.x or Swagger 2.x");
  }
  if (!document.paths || typeof document.paths !== "object") {
    throw new Error("OpenAPI document must contain a paths object");
  }

  const endpoints: ImportedEndpoint[] = [];
  for (const [path, pathItem] of Object.entries(document.paths)) {
    if (!path.startsWith("/") || !pathItem || typeof pathItem !== "object") continue;
    const sharedParameters = Array.isArray(pathItem.parameters) ? pathItem.parameters : [];
    for (const [method, rawOperation] of Object.entries(pathItem)) {
      if (!HTTP_METHODS.has(method) || !rawOperation || typeof rawOperation !== "object") continue;
      const operation = rawOperation as Record<string, unknown>;
      endpoints.push({
        method: method.toUpperCase(),
        path,
        operationId: typeof operation.operationId === "string" ? operation.operationId : null,
        summary: typeof operation.summary === "string"
          ? operation.summary
          : typeof operation.description === "string" ? operation.description.slice(0, 500) : null,
        parameters: [...sharedParameters, ...(Array.isArray(operation.parameters) ? operation.parameters : [])],
        requestBody: operation.requestBody ?? null,
        security: operation.security ?? null,
      });
    }
  }

  const baseUrl =
    document.servers?.[0]?.url ??
    (typeof document.basePath === "string" ? document.basePath : null);

  return { version, baseUrl, endpoints };
}

export function resolveEndpointUrl(baseUrl: string, endpointBaseUrl: string | null, path: string): string {
  const selectedBase = endpointBaseUrl || baseUrl;
  const url = new URL(selectedBase, baseUrl);
  const normalizedBase = url.pathname.replace(/\/+$/, "");
  url.pathname = `${normalizedBase}/${path.replace(/^\/+/, "")}`;
  return url.toString();
}

export function sampleEndpointValue(parameter: Record<string, unknown>): string {
  const example = parameter.example;
  if (typeof example === "string" || typeof example === "number" || typeof example === "boolean") {
    return String(example);
  }
  const schema = parameter.schema as Record<string, unknown> | undefined;
  const schemaExample = schema?.example;
  if (typeof schemaExample === "string" || typeof schemaExample === "number" || typeof schemaExample === "boolean") {
    return String(schemaExample);
  }
  const schemaType = schema?.type;
  if (schemaType === "integer" || schemaType === "number") return "1";
  if (schemaType === "boolean") return "true";
  if (schemaType === "array") return "1";
  return "sentinelx";
}

export function buildEndpointRequestUrl(
  baseUrl: string,
  endpointBaseUrl: string | null,
  endpoint: ImportedEndpoint,
): { url: string; parameters: string[] } {
  let url = resolveEndpointUrl(baseUrl, endpointBaseUrl, endpoint.path);
  const usedParameters: string[] = [];
  const parsed = endpoint.parameters.filter((value): value is Record<string, unknown> => Boolean(value && typeof value === "object"));
  for (const parameter of parsed) {
    const name = typeof parameter.name === "string" ? parameter.name : null;
    const location = typeof parameter.in === "string" ? parameter.in : null;
    if (!name || !location) continue;
    const value = sampleEndpointValue(parameter);
    if (location === "path") {
      url = url.replace(`{${name}}`, encodeURIComponent(value));
      usedParameters.push(`${name}=${value}`);
    } else if (location === "query") {
      const separator = url.includes("?") ? "&" : "?";
      url += `${separator}${encodeURIComponent(name)}=${encodeURIComponent(value)}`;
      usedParameters.push(`${name}=${value}`);
    }
  }
  return { url, parameters: usedParameters };
}