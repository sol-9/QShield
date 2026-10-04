/// <reference types="vite/client" />
interface ImportMetaEnv {
  readonly VITE_QSHIELD_PROGRAM_ID?: string;
  readonly VITE_QSHIELD_CLUSTER?: string;
  readonly VITE_QSHIELD_RPC_URL?: string;
  readonly VITE_QSHIELD_RELAYER_URL?: string;
}
