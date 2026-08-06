import * as TabsPrimitive from '@radix-ui/react-tabs'
import type * as React from 'react'
import { cn } from '@/lib/utils'

export const Tabs = TabsPrimitive.Root

export const TabsList = ({ className, ...props }: React.ComponentProps<typeof TabsPrimitive.List>) => (
  <TabsPrimitive.List
    className={cn('inline-flex items-center gap-1 rounded-lg border border-line bg-panel p-1', className)}
    {...props}
  />
)

export const TabsTrigger = ({ className, ...props }: React.ComponentProps<typeof TabsPrimitive.Trigger>) => (
  <TabsPrimitive.Trigger
    className={cn(
      'inline-flex cursor-pointer items-center gap-2 rounded-md px-3 py-1.5 text-sm font-medium text-muted transition-colors',
      'hover:text-ink data-[state=active]:bg-accent data-[state=active]:text-bg',
      className
    )}
    {...props}
  />
)

export const TabsContent = ({ className, ...props }: React.ComponentProps<typeof TabsPrimitive.Content>) => (
  <TabsPrimitive.Content className={cn('mt-6 focus-visible:outline-none', className)} {...props} />
)
