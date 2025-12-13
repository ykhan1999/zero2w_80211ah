import React, { createContext, useContext, useMemo, useState } from "react";

const WizardCtx = createContext(null);

export function WizardProvider({ children }) {
  const [answers, setAnswers] = useState({
    mode: "scan",
    target: "",
    verbosity: "normal",
    dryRun: false
  });

  const value = useMemo(() => ({ answers, setAnswers }), [answers]);
  return <WizardCtx.Provider value={value}>{children}</WizardCtx.Provider>;
}

export function useWizard() {
  const ctx = useContext(WizardCtx);
  if (!ctx) throw new Error("useWizard must be used inside WizardProvider");
  return ctx;
}
