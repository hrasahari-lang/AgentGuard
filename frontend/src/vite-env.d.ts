/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly PROD: boolean;
  readonly VITE_AGENTGUARD_API_ORIGIN?: string;
  readonly VITE_AGENTGUARD_ALLOWED_API_HOSTS?: string;
}
