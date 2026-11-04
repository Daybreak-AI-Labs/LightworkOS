import {Platform} from 'react-native';
import {requireOptionalNativeModule} from 'expo-modules-core';

type Reply = {status: number; body: string; headers?: Record<string, string>};
type Transport = {request(id: string, url: string, method: string, headers: Record<string, string>, body: string | null): Promise<Reply>; cancel(id: string): void};
const transport = requireOptionalNativeModule<Transport>('LightworkTransport');
export const nativePlatform = Platform.OS === 'ios' || Platform.OS === 'android';
export const nativeTransportReady = Boolean(transport);
let sequence = 0;

export async function nativeRequest(url: string, method: string, headers: Record<string, string>, body: string | undefined, signal: AbortSignal): Promise<Reply> {
  if (!transport) throw new Error('Install the packaged Lightwork preview. Expo Go does not contain its bounded transport.');
  const identifier = Date.now().toString(36) + '-' + (++sequence).toString(36);
  if (signal.aborted) throw new Error('Request cancelled.');
  const cancel = () => transport.cancel(identifier);
  signal.addEventListener('abort', cancel, {once: true});
  try {
    return await transport.request(identifier, url, method, headers, body ?? null);
  } catch (failure) {
    // Native errors intentionally contain no URL, bearer, response or draft.
    const code = (failure as {code?: string})?.code;
    if (code === 'E_TOO_LARGE') throw new Error('The dashboard sent too much information. Open the full dashboard.');
    if (code === 'E_REDIRECT') throw new Error('The dashboard redirected the request. Check the saved dashboard address.');
    if (code === 'E_CANCELLED' || signal.aborted) throw new Error('Request cancelled.');
    throw new Error('The dashboard connection could not finish. Check your network and try again.');
  } finally {signal.removeEventListener('abort', cancel);}
}
