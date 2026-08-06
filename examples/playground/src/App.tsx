import { FileSearch, IdCard, ListChecks, Send } from 'lucide-react'
import { useState } from 'react'
import { GithubMark } from '@/components/icons'
import { Button } from '@/components/ui/button'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Decode } from '@/tabs/Decode'
import { Issue, type IssueResult } from '@/tabs/Issue'
import { Present } from '@/tabs/Present'
import { VicalTab } from '@/tabs/VicalTab'

export const App = () => {
  const [tab, setTab] = useState('decode')
  const [decodeInput, setDecodeInput] = useState('')
  const [vicalInput, setVicalInput] = useState('')
  const [issuerSigned, setIssuerSigned] = useState('')
  const [deviceKey, setDeviceKey] = useState('')

  const onIssued = (result: IssueResult) => {
    setIssuerSigned(result.encoded)
    setDeviceKey(result.devicePrivateKeyJwk)
  }

  return (
    <div className="mx-auto flex min-h-screen max-w-[92rem] flex-col gap-8 px-6 py-8">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">mdoc playground</h1>
          <p className="mt-1 text-sm text-muted">
            Decode, issue and present ISO/IEC 18013-5 documents. Everything runs in this tab — no document, key or
            certificate is sent anywhere.
          </p>
        </div>
        <Button asChild variant="outline" className="gap-2.5 [&_svg]:size-5!">
          <a href="https://github.com/lukasjhan/mdoc" target="_blank" rel="noreferrer">
            <GithubMark /> lukasjhan/mdoc
          </a>
        </Button>
      </header>

      <Tabs value={tab} onValueChange={setTab} className="flex flex-col">
        <TabsList className="self-start">
          <TabsTrigger value="decode">
            <FileSearch /> Decode
          </TabsTrigger>
          <TabsTrigger value="issue">
            <IdCard /> Issue
          </TabsTrigger>
          <TabsTrigger value="present">
            <Send /> Present
          </TabsTrigger>
          <TabsTrigger value="vical">
            <ListChecks /> VICAL
          </TabsTrigger>
        </TabsList>

        <TabsContent value="decode">
          <Decode input={decodeInput} onInput={setDecodeInput} />
        </TabsContent>

        <TabsContent value="issue">
          <Issue onIssued={onIssued} />
        </TabsContent>

        <TabsContent value="present">
          <Present
            issuerSigned={issuerSigned}
            devicePrivateKeyJwk={deviceKey}
            onIssuerSigned={setIssuerSigned}
            onDeviceKey={setDeviceKey}
            onPresented={(value) => {
              setDecodeInput(value)
              setTab('decode')
            }}
          />
        </TabsContent>

        <TabsContent value="vical">
          <VicalTab input={vicalInput} onInput={setVicalInput} />
        </TabsContent>
      </Tabs>

      <footer className="mt-auto border-t border-line pt-4 text-xs text-muted">
        Built on <code className="text-ink">@m-doc/core</code>, <code className="text-ink">@m-doc/context</code>,{' '}
        <code className="text-ink">@m-doc/mdl</code> and <code className="text-ink">@m-doc/vical</code>.
      </footer>
    </div>
  )
}
