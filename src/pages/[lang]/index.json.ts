import type { APIRoute } from "astro";
import { langPaths, type Lang } from "../../i18n";
import { index } from "../../data";
export const getStaticPaths = langPaths;
export const GET: APIRoute = async ({ params }) => new Response(JSON.stringify(await index(params.lang as Lang)), { headers: { "Content-Type": "application/json" } });
