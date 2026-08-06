import type * as React from 'react'
import { cn } from '@/lib/utils'

export const Textarea = ({ className, ...props }: React.ComponentProps<'textarea'>) => (
  <textarea
    className={cn(
      'w-full rounded-md border border-line bg-bg px-3 py-2 font-mono text-xs leading-relaxed',
      'placeholder:text-muted focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-accent',
      className
    )}
    {...props}
  />
)
