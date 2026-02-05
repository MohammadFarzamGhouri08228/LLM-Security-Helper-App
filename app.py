import os
import json
import streamlit as st
from dotenv import load_dotenv
from pydantic import BaseModel, Field
from typing import List, Optional, Literal

# Gemini (Commented out)
# from google import genai
# from google.genai import types

# Groq
from groq import Groq

# Hugging Face
from huggingface_hub import InferenceClient

# -----------------------------
# JSON Schemas (Pydantic)
# -----------------------------
Severity = Literal["critical", "high", "medium", "low", "info"]

class CodeFixItem(BaseModel):
    vulnerability: str
    severity: Severity
    where: str = Field(description="File/line or description of location in snippet")
    why_it_matters: str
    exploit_example: str
    recommended_fix: str = Field(description="Concrete fix steps")
    fixed_code_snippet: Optional[str] = None
    verification: List[str] = Field(default_factory=list, description="How to test the fix")

class CodeAnalysisResult(BaseModel):
    summary: str
    findings: List[CodeFixItem]
    top_priority_actions: List[str]

class SpecRiskItem(BaseModel):
    risk_title: str
    owasp_llm_category: str = Field(description="e.g., LLM01 Prompt Injection")
    atlas_perspective: str = Field(description="ATLAS-style tactic/technique description (plain English ok)")
    scenario: str
    impact: str
    likelihood: Literal["high", "medium", "low"]
    mitigations: List[str]
    tests: List[str]

class SpecsAnalysisResult(BaseModel):
    system_overview: str
    assumptions: List[str]
    risks: List[SpecRiskItem]
    hardening_checklist: List[str]


# -----------------------------
# Helpers
# -----------------------------
def load_prompt(path: str, fallback: str) -> str:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read().strip()
    except Exception:
        return fallback

def pretty_json(obj) -> str:
    return json.dumps(obj, indent=2, ensure_ascii=False)

# def call_gemini_json(api_key: str, model: str, system_prompt: str, user_text: str, schema_model: BaseModel):
#     client = genai.Client(api_key=api_key)
#     resp = client.models.generate_content(
#         model=model,
#         contents=[
#             types.Content(
#                 role="user",
#                 parts=[types.Part(text=f"{system_prompt}\n\nUSER_INPUT:\n{user_text}")]
#             )
#         ],
#         config=types.GenerateContentConfig(
#             response_mime_type="application/json",
#             response_json_schema=schema_model.model_json_schema(),
#             thinking_config=types.ThinkingConfig(thinking_level="minimal"),
#         ),
#     )
#     return json.loads(resp.text)

def call_groq_json(api_key: str, model: str, system_prompt: str, user_text: str, schema_model: BaseModel):
    client = Groq(api_key=api_key)
    schema_hint = schema_model.model_json_schema()
    messages = [
        {"role": "system", "content": system_prompt + "\nReturn STRICT JSON only."},
        {"role": "user", "content": f"Return JSON matching this schema:\n{json.dumps(schema_hint)}\n\nUSER_INPUT:\n{user_text}"}
    ]
    completion = client.chat.completions.create(
        model=model,
        messages=messages,
        temperature=0.2,
    )
    raw = completion.choices[0].message.content.strip()
    
    # Clean up Markdown code fences
    if raw.startswith("```"):
        lines = raw.split("\n")
        if len(lines) >= 2:
            raw = "\n".join(lines[1:-1])
    
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        raise ValueError(f"Groq did not return JSON. Raw response:\n{raw}")

def call_huggingface_json(api_key: str, model: str, system_prompt: str, user_text: str, schema_model: BaseModel):
    client = InferenceClient(api_key=api_key)
    schema_hint = schema_model.model_json_schema()
    
    prompt = f"""
    {system_prompt}
    
    OUTPUT SCHEMA:
    {json.dumps(schema_hint)}
    
    USER INPUT:
    {user_text}
    
    Return ONLY VALID JSON.
    """
    
    messages = [
        {"role": "user", "content": prompt}
    ]
    
    # HF serverless often needs max_tokens specified
    response = client.chat_completion(
        model=model,
        messages=messages,
        max_tokens=2048,
        temperature=0.3
    )
    
    raw = response.choices[0].message.content.strip()
    
    # Clean up Markdown code fences
    if raw.startswith("```"):
        lines = raw.split("\n")
        if len(lines) >= 2:
            raw = "\n".join(lines[1:-1])
            
    # ROBUST JSON EXTRACTION
    # The model might return "{Schema} {Response}" or other noise.
    # We scan backwards from the last '}' to find the last valid JSON object.
    
    text = raw.strip()
    end_idx = text.rfind('}')
    
    if end_idx != -1:
        # Start looking for the matching opening brace from the end
        curr = end_idx - 1
        while curr >= 0:
            if text[curr] == '{':
                candidate = text[curr : end_idx+1]
                try:
                    obj = json.loads(candidate)
                    # We found a valid JSON object! 
                    # Filter out if it's just the Schema (contains "$defs" or "properties" at root)
                    if "$defs" not in obj and "properties" not in obj:
                        return obj
                except json.JSONDecodeError:
                    pass # Keep looking backwards
            curr -= 1

    # Fallback: try parsing the whole thing (e.g. if it was just one object)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        raise ValueError(f"Hugging Face did not return JSON. Raw response:\n{raw}")

def run_with_fallback(primary_fn, primary_name, fallback_fn, fallback_name):
    try:
        return primary_fn(), primary_name
    except Exception as e1:
        try:
            return fallback_fn(), fallback_name
        except Exception as e2:
            raise RuntimeError(f"{primary_name} failed: {e1}\n{fallback_name} failed: {e2}")

# -----------------------------
# UI Display Helpers
# -----------------------------
def display_code_analysis(data):
    st.success("Analysis Complete!")
    
    # Summary
    st.markdown(f"### 🛡️ Analysis Summary\n{data.get('summary', 'No summary provided.')}")

    # Findings
    findings = data.get('findings', [])
    if not findings:
        st.info("No vulnerabilities found! Great job.")
    else:
        st.markdown("### 🚨 Vulnerabilities Found")
    
    for i, finding in enumerate(findings):
        severity = finding.get('severity', 'low').lower()
        
        # Color coding
        if severity in ["critical", "high"]:
            icon = "🔴"
            color = "red"
        elif severity == "medium":
            icon = "🟠"
            color = "orange"
        else:
            icon = "🔵"
            color = "blue"
            
        with st.expander(f"{icon} {finding.get('vulnerability')} ({severity.upper()})", expanded=True):
            c1, c2 = st.columns([2, 1])
            with c1:
                st.markdown(f"**📍 Location:** `{finding.get('where')}`")
                st.markdown(f"**❓ Why it matters:**\n{finding.get('why_it_matters')}")
            with c2:
                 st.markdown(f"**💣 Exploit Example:**\n`{finding.get('exploit_example')}`")
            
            st.divider()
            
            st.markdown(f"**🛠️ Recommended Fix:**\n{finding.get('recommended_fix')}")
            
            fixed_code = finding.get('fixed_code_snippet')
            if fixed_code:
                st.markdown("##### ✅ Fixed Code Snippet:")
                st.code(fixed_code, language="python")
            
            if finding.get('verification'):
                st.markdown("**🧪 Verification Steps:**")
                for step in finding.get('verification', []):
                    st.markdown(f"- {step}")

    # Actions
    if data.get('top_priority_actions'):
        st.markdown("### ⚡ Top Priority Actions")
        for action in data.get('top_priority_actions', []):
            st.markdown(f"- [ ] {action}")

def display_specs_analysis(data):
    st.success("Analysis Complete!")
    
    # Overview
    st.markdown(f"### 🏗️ System Overview\n{data.get('system_overview', '')}")
    
    if data.get('assumptions'):
        with st.expander("ℹ️ Assumptions made by AI"):
            for asm in data.get('assumptions', []):
                st.markdown(f"- {asm}")

    # Risks
    st.markdown("### ⚠️ Identified Security Risks (OWASP LLM + ATLAS)")
    risks = data.get('risks', [])
    
    for risk in risks:
        likelihood = risk.get('likelihood', 'low').lower()
        icon = "🚩" if likelihood == "high" else "⚠️"
        
        with st.expander(f"{icon} {risk.get('risk_title')} (Likelihood: {likelihood.upper()})", expanded=True):
            st.markdown(f"**🏷️ OWASP Category:** `{risk.get('owasp_llm_category')}`")
            st.markdown(f"**🗺️ ATLAS Perspective:** `{risk.get('atlas_perspective')}`")
            
            st.markdown("---")
            st.markdown(f"**📝 Attack Scenario:** {risk.get('scenario')}")
            st.markdown(f"**💥 Potential Impact:** {risk.get('impact')}")
            
            st.markdown("---")
            c1, c2 = st.columns(2)
            with c1:
                st.markdown("**🛡️ Mitigations:**")
                for m in risk.get('mitigations', []):
                    st.markdown(f"- {m}")
            with c2:
                st.markdown("**🧪 Validation Tests:**")
                for t in risk.get('tests', []):
                    st.markdown(f"- {t}")

    # Checklist
    if data.get('hardening_checklist'):
        st.markdown("### ✅ Hardening Checklist")
        for item in data.get('hardening_checklist', []):
            st.markdown(f"- [ ] {item}")


# -----------------------------
# Streamlit UI
# -----------------------------
st.set_page_config(page_title="LLM Security Helper", layout="wide")
st.title("LLM Security Helper")

load_dotenv()

# GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
# GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-flash-latest")

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")

HUGGINGFACE_API_KEY = os.getenv("HUGGINGFACE_API_KEY", "")
# Using a strong instruction tuned model available on serverless API
HUGGINGFACE_MODEL = os.getenv("HUGGINGFACE_MODEL", "meta-llama/Meta-Llama-3-8B-Instruct")

with st.sidebar:
    st.header("Provider Settings")
    
    # Provider Selection
    provider_options = ["Groq", "Hugging Face"]
    selected_provider = st.radio("Select Primary Provider", provider_options, index=0)
    
    backup_provider = "Hugging Face" if selected_provider == "Groq" else "Groq"
    enable_fallback = st.checkbox(f"Auto fallback to {backup_provider} if failed", value=True)

    st.divider()
    
    st.subheader("Groq Settings")
    groq_model = st.text_input("Groq Model", value=GROQ_MODEL)
    
    st.subheader("Hugging Face Settings")
    hf_model = st.text_input("HF Model ID", value=HUGGINGFACE_MODEL)

    st.divider()
    st.caption("Keys are read from .env")
    if not GROQ_API_KEY:
        st.warning("Missing GROQ_API_KEY in .env")
    if not HUGGINGFACE_API_KEY:
        st.warning("Missing HUGGINGFACE_API_KEY in .env")

code_prompt = load_prompt("prompts/code_security.md", "You are an AppSec expert. Return strict JSON only.")
specs_prompt = load_prompt("prompts/specs_security.md", "You are a GenAI AppSec expert. Return strict JSON only.")

tab1, tab2 = st.tabs(["Part 1: Code → Security Fixes", "Part 2: Specs → OWASP LLM + ATLAS Risks"])

with tab1:
    st.subheader("Paste code (vulnerable snippet) → get vulnerabilities + fixes")
    colA, colB = st.columns([1,1])
    with colA:
        language = st.selectbox("Language (optional)", ["auto", "Python", "JavaScript", "Java", "PHP", "C#", "SQL", "Other"])
        code_input = st.text_area("Code snippet", height=350, placeholder="Paste code here...")
        analyze_code = st.button("Analyze Code", type="primary")
    with colB:
        st.markdown("**Output** (security-only, prioritized)")
        # output_box = st.empty() # Removed raw output box

    if analyze_code:
        # Check keys based on selection
        primary_key = GROQ_API_KEY if selected_provider == "Groq" else HUGGINGFACE_API_KEY
        backup_key = HUGGINGFACE_API_KEY if selected_provider == "Groq" else GROQ_API_KEY
        
        if not primary_key and not (enable_fallback and backup_key):
             st.error(f"No API key available for {selected_provider}. Check .env file.")
        elif not code_input.strip():
            st.error("Paste some code first.")
        else:
            user_text = f"LANGUAGE: {language}\n\nCODE:\n{code_input}"

            # Define functions based on current config
            def call_groq():
                return call_groq_json(
                    api_key=GROQ_API_KEY,
                    model=groq_model,
                    system_prompt=code_prompt,
                    user_text=user_text,
                    schema_model=CodeAnalysisResult,
                )
            
            def call_hf():
                return call_huggingface_json(
                    api_key=HUGGINGFACE_API_KEY,
                    model=hf_model,
                    system_prompt=code_prompt,
                    user_text=user_text,
                    schema_model=CodeAnalysisResult,
                )

            # Assign primary/fallback
            if selected_provider == "Groq":
                primary_fn = call_groq
                fallback_fn = call_hf
                p_name, b_name = "Groq", "Hugging Face"
            else:
                primary_fn = call_hf
                fallback_fn = call_groq
                p_name, b_name = "Hugging Face", "Groq"

            try:
                if enable_fallback and backup_key:
                    data, used = run_with_fallback(primary_fn, p_name, fallback_fn, b_name)
                else:
                    data = primary_fn()
                    used = p_name
                
                # Use new display function inside column B
                with colB:
                    display_code_analysis(data)
                    st.caption(f"Analysis provider: {used}")
                    
            except Exception as e:
                st.error(str(e))

with tab2:
    st.subheader("Paste GenAI/Agentic app specs → OWASP LLM Top 10 + ATLAS-style threats + mitigations")
    colA, colB = st.columns([1,1])
    with colA:
        specs_input = st.text_area(
            "App specs / use case",
            height=350,
            placeholder="Describe your GenAI/agentic app: users, data, tools, RAG, memory, auth, deployment, etc."
        )
        analyze_specs = st.button("Analyze Specs", type="primary")
    with colB:
        st.markdown("**Output** (mapped + actionable)")
        # output_box2 = st.empty() # Removed raw output box

    if analyze_specs:
        primary_key = GROQ_API_KEY if selected_provider == "Groq" else HUGGINGFACE_API_KEY
        backup_key = HUGGINGFACE_API_KEY if selected_provider == "Groq" else GROQ_API_KEY
        
        if not primary_key and not (enable_fallback and backup_key):
             st.error(f"No API key available for {selected_provider}. Check .env file.")
        elif not specs_input.strip():
            st.error("Paste specs first.")
        else:
            user_text = specs_input

            # Define functions
            def call_groq():
                return call_groq_json(
                    api_key=GROQ_API_KEY,
                    model=groq_model,
                    system_prompt=specs_prompt,
                    user_text=user_text,
                    schema_model=SpecsAnalysisResult,
                )
            
            def call_hf():
                return call_huggingface_json(
                    api_key=HUGGINGFACE_API_KEY,
                    model=hf_model,
                    system_prompt=specs_prompt,
                    user_text=user_text,
                    schema_model=SpecsAnalysisResult,
                )

            # Assign primary/fallback
            if selected_provider == "Groq":
                primary_fn = call_groq
                fallback_fn = call_hf
                p_name, b_name = "Groq", "Hugging Face"
            else:
                primary_fn = call_hf
                fallback_fn = call_groq
                p_name, b_name = "Hugging Face", "Groq"

            try:
                if enable_fallback and backup_key:
                    data, used = run_with_fallback(primary_fn, p_name, fallback_fn, b_name)
                else:
                    data = primary_fn()
                    used = p_name
                
                # Use new display function inside column B
                with colB:
                    display_specs_analysis(data)
                    st.caption(f"Analysis provider: {used}")
                    
            except Exception as e:
                st.error(str(e))
