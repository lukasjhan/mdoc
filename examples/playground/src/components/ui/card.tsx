import type * as React from 'react'
import { cn } from '@/lib/utils'

export const Card = ({ className, ...props }: React.ComponentProps<'div'>) => (
  <div className={cn('rounded-lg border border-line bg-panel', className)} {...props} />
)

export const CardHeader = ({ className, ...props }: React.ComponentProps<'div'>) => (
  <div className={cn('flex flex-col gap-1 border-b border-line px-4 py-3', className)} {...props} />
)

export const CardTitle = ({ className, ...props }: React.ComponentProps<'h3'>) => (
  <h3 className={cn('text-sm font-semibold tracking-tight', className)} {...props} />
)

export const CardDescription = ({ className, ...props }: React.ComponentProps<'p'>) => (
  <p className={cn('text-xs text-muted', className)} {...props} />
)

export const CardContent = ({ className, ...props }: React.ComponentProps<'div'>) => (
  <div className={cn('p-4', className)} {...props} />
)
