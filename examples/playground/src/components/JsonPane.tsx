import { Check, Copy } from 'lucide-react'
import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'

export const CopyButton = ({ value, className }: { value: string; className?: string }) => {
  const [copied, setCopied] = useState(false)

  return (
    <Button
      variant="ghost"
      size="icon"
      className={className}
      title="Copy"
      onClick={() => {
        void navigator.clipboard.writeText(value)
        setCopied(true)
        setTimeout(() => setCopied(false), 1200)
      }}
    >
      {copied ? <Check className="text-good" /> : <Copy />}
    </Button>
  )
}

export const JsonPane = ({ value, className }: { value: string; className?: string }) => (
  <div className={cn('relative', className)}>
    <CopyButton value={value} className="absolute right-4 top-2 z-10 bg-bg" />
    <pre className="max-h-[28rem] overflow-auto rounded-md border border-line bg-bg p-3 pr-12 font-mono text-xs leading-relaxed">
      {value}
    </pre>
  </div>
)

export const Field = ({ label, children }: { label: string; children: React.ReactNode }) => (
  <div className="flex flex-col gap-1 border-b border-line py-2 last:border-b-0">
    <span className="text-[0.7rem] uppercase tracking-wide text-muted">{label}</span>
    <span className="break-all font-mono text-xs">{children}</span>
  </div>
)
