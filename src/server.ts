import "dotenv/config";
import app from "./app";
import { config } from "./config";

app.listen(config.port, () => {
  console.log(`Server running on port ${config.port} in ${config.nodeEnv} mode`);
});
