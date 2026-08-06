import { Upload } from 'lucide-react'
import { type DragEvent, useRef, useState } from 'react'
import { Button } from '@/components/ui/button'
import { describeError, readFileAsInput } from '@/lib/mdoc'

type Props = {
  /** Receives the file's contents, already normalised to something `parseInput` accepts. */
  onLoad: (value: string) => void
  onError: (message: string) => void
  accept?: string
  children?: React.ReactNode
}

const load = async (file: File | undefined, { onLoad, onError }: Props) => {
  if (!file) return

  try {
    onLoad(await readFileAsInput(file))
  } catch (error) {
    onError(describeError(error))
  }
}

/** A button that opens the file picker. Pair it with `useFileDrop` for the same file by drag. */
export const FileButton = (props: Props) => {
  const input = useRef<HTMLInputElement>(null)

  return (
    <>
      <input
        ref={input}
        type="file"
        accept={props.accept}
        className="hidden"
        onChange={(event) => {
          void load(event.target.files?.[0], props)
          event.target.value = ''
        }}
      />
      <Button variant="outline" size="sm" onClick={() => input.current?.click()}>
        <Upload /> {props.children ?? 'Upload'}
      </Button>
    </>
  )
}

/** Drop handlers for whatever region should accept the same file. */
export const useFileDrop = (props: Props) => {
  const [over, setOver] = useState(false)

  const end = (event: DragEvent) => {
    event.preventDefault()
    setOver(false)
  }

  return {
    over,
    handlers: {
      onDragOver: (event: DragEvent) => {
        event.preventDefault()
        setOver(true)
      },
      onDragLeave: end,
      onDrop: (event: DragEvent) => {
        end(event)
        void load(event.dataTransfer.files[0], props)
      },
    },
  }
}
