import { createClient } from "redis";

const client = await createClient().connect();

export default client;