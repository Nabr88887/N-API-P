import { useState } from 'react'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'

import { ModalDialog } from './ModalDialog'

function DialogHarness() {
  const [open, setOpen] = useState(false)

  return <>
    <button type="button" onClick={() => setOpen(true)}>Open dialog</button>
    {open && <ModalDialog ariaLabelledBy="test-dialog-title" onDismiss={() => setOpen(false)}>
      <h2 id="test-dialog-title">Test dialog</h2>
      <button type="button">First action</button>
      <button type="button">Last action</button>
    </ModalDialog>}
  </>
}

describe('ModalDialog', () => {
  it('traps focus, closes on Escape, and restores the opener', async () => {
    const user = userEvent.setup()
    render(<DialogHarness />)
    const opener = screen.getByRole('button', { name: 'Open dialog' })

    await user.click(opener)
    const dialog = screen.getByRole('dialog', { name: 'Test dialog' })
    expect(dialog).toHaveFocus()

    await user.tab({ shift: true })
    expect(screen.getByRole('button', { name: 'Last action' })).toHaveFocus()
    await user.tab()
    expect(screen.getByRole('button', { name: 'First action' })).toHaveFocus()

    await user.keyboard('{Escape}')
    expect(screen.queryByRole('dialog', { name: 'Test dialog' })).not.toBeInTheDocument()
    expect(opener).toHaveFocus()
  })
})
