-- Filtro do pandoc: símbolos que a fonte padrão do LaTeX não tem viram matemática (só na geração do PDF).
local map = {
  ["≤"] = "$\\leq$", ["≥"] = "$\\geq$", ["≈"] = "$\\approx$", ["⇒"] = "$\\Rightarrow$",
  ["↑"] = "$\\uparrow$", ["↓"] = "$\\downarrow$",
}
function Str(el)
  local out, buf, hit = {}, "", false
  for _, c in utf8.codes(el.text) do
    local ch = utf8.char(c)
    if map[ch] then
      hit = true
      if buf ~= "" then out[#out + 1] = pandoc.Str(buf); buf = "" end
      out[#out + 1] = pandoc.RawInline("latex", map[ch])
    else
      buf = buf .. ch
    end
  end
  if not hit then return nil end
  if buf ~= "" then out[#out + 1] = pandoc.Str(buf) end
  return out
end
