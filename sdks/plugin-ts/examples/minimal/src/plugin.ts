import { defineValidatedTool, servePlugin } from "@maverick/plugin-sdk";

const greet = defineValidatedTool({
  name: "greet", description: "Greet a reviewed name without external effects.",
  inputSchema: {type: "object", properties: {who: {type: "string", minLength: 1, maxLength: 100}}, required: ["who"], additionalProperties: false},
  parseArgs(input: unknown): {who: string} {
    if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error("object required");
    const args = input as Record<string, unknown>;
    if (Object.keys(args).length !== 1 || typeof args.who !== "string" || !args.who.trim() || args.who.length > 100) throw new Error("a bounded name is required");
    return {who: args.who};
  },
  handler: ({who}) => `Hello, ${who}!`,
});

await servePlugin([greet]);
