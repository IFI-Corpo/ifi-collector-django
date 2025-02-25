import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

export default function inputAPI() {
  return (
    <div className="*:not-first:mt-2">
      <Label>Input with button</Label>
      <div className="flex gap-2">
        <Input className="flex-1" placeholder="Email" type="email" />
        <Button variant="outline">Send</Button>
      </div>
    </div>
  );
}
