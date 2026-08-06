import type * as React from 'react'
import { cn } from '@/lib/utils'

export const Input = ({ className, ...props }: React.ComponentProps<'input'>) => (
  <input
    className={cn(
      'h-9 w-full rounded-md border border-line bg-bg px-3 py-1 text-sm',
      'placeholder:text-muted focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-accent',
      'disabled:cursor-not-allowed disabled:opacity-50',
      className
    )}
    {...props}
  />
)
