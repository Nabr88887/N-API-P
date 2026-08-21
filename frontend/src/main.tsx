import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'

import { Portal } from './Portal'
import { createPortalClient } from './portal-api'

const rootElement = document.getElementById('root')
if (rootElement === null) {
  throw new Error('application root is missing')
}

createRoot(rootElement).render(
  <StrictMode>
    <Portal client={createPortalClient()} />
  </StrictMode>,
)
