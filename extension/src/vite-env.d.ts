/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_AGENT_BASE_URL: string;
  readonly VITE_AGENT_HEALTH_TIMEOUT_MS?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}

