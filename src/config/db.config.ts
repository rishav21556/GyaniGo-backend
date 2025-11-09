
import { createClient } from '@supabase/supabase-js'
import { config } from 'dotenv'
config()
const supabaseUrl = process.env.SUPABASE_URL || ''
const supabaseKey = process.env.SUPABASE_API_KEY || ''
const supabase = createClient(supabaseUrl, supabaseKey)
const supabaseAdmin = createClient(supabaseUrl, process.env.SUPABASE_SERVICE_ROLE_KEY || '')

export { supabase, supabaseAdmin }