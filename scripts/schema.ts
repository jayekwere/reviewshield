import { z } from "zod";
import { requestSchema } from "../src/review.js";

console.log(JSON.stringify(z.toJSONSchema(requestSchema, { unrepresentable: "any" }), null, 2));
