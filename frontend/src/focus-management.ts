import type { KeyboardEvent } from 'react'

const focusableSelector = [
  'a[href]',
  'button:not([disabled])',
  'input:not([disabled])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  '[tabindex]:not([tabindex="-1"])',
].join(',')

export function trapTabKey(event: KeyboardEvent<HTMLElement>, container: HTMLElement) {
  if (event.key !== 'Tab') return

  event.stopPropagation()
  const focusable = Array.from(container.querySelectorAll<HTMLElement>(focusableSelector))
  const first = focusable[0]
  const last = focusable.at(-1)
  if (!first || !last) {
    event.preventDefault()
    container.focus()
    return
  }

  if (event.shiftKey && (document.activeElement === first || document.activeElement === container)) {
    event.preventDefault()
    last.focus()
  } else if (!event.shiftKey && document.activeElement === last) {
    event.preventDefault()
    first.focus()
  }
}
