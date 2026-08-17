import { useEffect, useRef, type KeyboardEvent, type ReactNode } from 'react'

import { trapTabKey } from './focus-management'

type Props = {
  ariaLabelledBy: string
  children: ReactNode
  className?: string
  onDismiss?: () => void
  raised?: boolean
}

export function ModalDialog({ ariaLabelledBy, children, className = '', onDismiss, raised = false }: Props) {
  const dialogRef = useRef<HTMLElement>(null)

  useEffect(() => {
    const previousFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null
    dialogRef.current?.focus()

    return () => {
      if (previousFocus?.isConnected) previousFocus.focus()
    }
  }, [])

  function handleKeyDown(event: KeyboardEvent<HTMLElement>) {
    if (event.key === 'Escape') {
      event.stopPropagation()
      if (onDismiss) {
        event.preventDefault()
        onDismiss()
      }
      return
    }
    const dialog = dialogRef.current
    if (!dialog) return
    trapTabKey(event, dialog)
  }

  const dialogClassName = `dialog${className ? ` ${className}` : ''}`
  const backdropClassName = `dialog-backdrop${raised ? ' dialog-backdrop-raised' : ''}`

  return <div className={backdropClassName} role="presentation">
    <section
      ref={dialogRef}
      className={dialogClassName}
      role="dialog"
      aria-modal="true"
      aria-labelledby={ariaLabelledBy}
      tabIndex={-1}
      onKeyDown={handleKeyDown}
    >
      {children}
    </section>
  </div>
}
