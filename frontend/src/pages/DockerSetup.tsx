import { useState } from "react";
import { motion } from "framer-motion";
import { useNavigate } from "react-router-dom";
import { Copy, CheckCircle2, ArrowLeft, ArrowRight } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert } from "@/components/ui/alert";

const dockerCommands = [
  {
    step: 1,
    title: "Pull the KratosComply agent image",
    command: "docker pull kratoscomply/agent:latest",
    description: "Download the official agent container",
  },
  {
    step: 2,
    title: "Run the scan on your repository",
    command: 'docker run -v "$(pwd):/workspace" kratoscomply/agent:latest scan /workspace --output /workspace/aegis-report.json',
    description: "Mount your repo and generate the compliance report",
  },
  {
    step: 3,
    title: "Generate your signing keypair",
    command: "docker run -v ~/.kratos/keys:/keys kratoscomply/agent:latest generate-key --keystore /keys",
    description: "Create ed25519 keys for report signing (one-time setup)",
  },
  {
    step: 4,
    title: "Sign your report",
    command: 'docker run -v "$(pwd):/workspace" -v ~/.kratos/keys:/keys kratoscomply/agent:latest scan /workspace --output /workspace/aegis-report.json --keystore /keys',
    description: "Generate a signed report with your private key",
  },
];

export function DockerSetupPage() {
  const navigate = useNavigate();
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);

  const copyToClipboard = (text: string, index: number) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  return (
    <div className="space-y-8 py-8">
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        className="flex items-center gap-4"
      >
        <Button variant="ghost" onClick={() => navigate("/")} className="gap-2">
          <ArrowLeft className="h-4 w-4" /> Back to landing
        </Button>
        <div>
          <h1 className="text-4xl font-semibold">Docker Agent Setup</h1>
          <p className="text-muted-foreground">Run KratosComply offline with full control</p>
        </div>
      </motion.div>

      <Alert
        type="info"
        title="Offline-first scanning"
        description="The Docker agent runs completely offline. Your source code never leaves your machine. Only upload the generated report when you're ready."
      />

      <div className="grid gap-6">
        {dockerCommands.map((item, idx) => (
          <motion.div
            key={item.step}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: idx * 0.1 }}
          >
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="flex items-center gap-2">
                      <span className="flex h-8 w-8 items-center justify-center rounded-full bg-primary/20 text-primary font-bold">
                        {item.step}
                      </span>
                      {item.title}
                    </CardTitle>
                    <CardDescription className="mt-2">{item.description}</CardDescription>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <div className="relative rounded-lg bg-muted/60 p-4 font-mono text-sm">
                  <code className="text-foreground">{item.command}</code>
                  <Button
                    variant="ghost"
                    size="icon"
                    className="absolute right-2 top-2"
                    onClick={() => copyToClipboard(item.command, idx)}
                  >
                    {copiedIndex === idx ? (
                      <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                    ) : (
                      <Copy className="h-4 w-4" />
                    )}
                  </Button>
                </div>
              </CardContent>
            </Card>
          </motion.div>
        ))}
      </div>

      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.5 }}
      >
        <Card className="bg-gradient-to-br from-indigo-500/10 to-purple-500/10 border-primary/20">
          <CardHeader>
            <CardTitle>Next: Upload your report</CardTitle>
            <CardDescription>
              Once you've generated aegis-report.json, navigate to the dashboard to upload it along with your public key for verification.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Button onClick={() => navigate("/dashboard")} className="gap-2">
              Go to Dashboard <ArrowRight className="h-4 w-4" />
            </Button>
          </CardContent>
        </Card>
      </motion.div>
    </div>
  );
}
