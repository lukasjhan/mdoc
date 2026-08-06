import { cva, type VariantProps } from 'class-variance-authority'
import type * as React from 'react'
import { cn } from '@/lib/utils'

const badgeVariants = cva('inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium', {
  variants: {
    tone: {
      neutral: 'bg-line text-muted',
      good: 'bg-good/15 text-good',
      warn: 'bg-warn/15 text-warn',
      bad: 'bg-bad/15 text-bad',
      accent: 'bg-accent/15 text-accent',
    },
  },
  defaultVariants: { tone: 'neutral' },
})

export const Badge = ({
  className,
  tone,
  ...props
}: React.ComponentProps<'span'> & VariantProps<typeof badgeVariants>) => (
  <span className={cn(badgeVariants({ tone }), className)} {...props} />
)
