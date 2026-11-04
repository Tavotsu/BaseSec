import { agentWarn, startAgentServer } from './channel';
import { installHooks } from './hooks';

/**
 * Entrada del preload (`node --require dist/agent.cjs`). Solo corre porque el usuario lo carga. Todo va en try/catch:
 * si algo falla, el agente avisa por stderr y la app sigue sin instrumentar.
 */
try {
  if (typeof process.setSourceMapsEnabled === 'function') process.setSourceMapsEnabled(true);
  const server = startAgentServer();
  if (server !== null) installHooks(server.emit);
} catch (error) {
  agentWarn(`initialization failed, running without instrumentation: ${error instanceof Error ? error.message : String(error)}`);
}
