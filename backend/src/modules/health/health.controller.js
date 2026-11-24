import { getProcessHealth } from './health.service.js';

export function getHealth(request, response) {
  const result = getProcessHealth();

  response.status(200).json(result);
}