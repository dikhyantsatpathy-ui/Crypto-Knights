// ============================================================================
// Synthetic Document Specimen Generator for SIH26188 Screening Desk
// Generates high-fidelity PNG specimens on an HTML5 canvas for 1-click testing:
// - Clean Indian Passport (ICAO Doc 9303 TD3 valid check digits)
// - Tampered Passport (Photo Swapped, Discrepant Check Digits, Noise Anomaly)
// - Cross-Border Syndicate Imposter (Panitanki / Raxaul Identity Clash)
// - Indian Driving Licence (MoRTH Validated Format)
// - Indian Permanent Account Number (PAN Card)
// ============================================================================

import type { ScreenDocType } from "../api";

export interface SpecimenPreset {
  id: string;
  title: string;
  badge: string;
  docType: ScreenDocType;
  checkpoint: string;
  docNumber: string;
  description: string;
  filename: string;
}

export const SPECIMEN_PRESETS: SpecimenPreset[] = [
  {
    id: "passport_clean",
    title: "Clean Indian Passport",
    badge: "ICAO TD3 Valid",
    docType: "passport",
    checkpoint: "Raxaul ICP (Bihar/Nepal Border)",
    docNumber: "L898902C",
    description: "Official ICAO 9303 specimen with matching checksums and valid MRZ lines.",
    filename: "passport_icao9303_clean.png",
  },
  {
    id: "passport_tampered",
    title: "Tampered Passport (Altered MRZ)",
    badge: "Forged / Tampered",
    docType: "passport",
    checkpoint: "Panitanki ICP (WB/Nepal Border)",
    docNumber: "L898902C",
    description: "Altered DOB and invalid MRZ check digit. Elevated tampering risk score.",
    filename: "passport_tampered_mrz.png",
  },
  {
    id: "passport_syndicate",
    title: "Syndicate Imposter Passport",
    badge: "🚨 Syndicate Clash",
    docType: "passport",
    checkpoint: "Panitanki ICP (WB/Nepal Border)",
    docNumber: "P9876543",
    description: "Document presented under different name at a cross-border checkpoint.",
    filename: "passport_syndicate_clash.png",
  },
  {
    id: "driving_licence",
    title: "Indian Driving Licence",
    badge: "MoRTH Verified",
    docType: "driving_licence",
    checkpoint: "Jogbani ICP (Bihar/Nepal Border)",
    docNumber: "DL-0420110012345",
    description: "Indian Union Driving Licence with state RTO format and validity.",
    filename: "driving_licence_morth.png",
  },
  {
    id: "pan_card",
    title: "Indian PAN Card",
    badge: "ITD Verified",
    docType: "pan",
    checkpoint: "Jaigaon ICP (WB/Bhutan Border)",
    docNumber: "ABCDE1234F",
    description: "Income Tax Department Permanent Account Number format with 4th-char check.",
    filename: "pan_card_income_tax.png",
  },
];

export async function generateSpecimenFile(preset: SpecimenPreset): Promise<File> {
  const canvas = document.createElement("canvas");
  canvas.width = 900;
  canvas.height = 580;
  const ctx = canvas.getContext("2d");
  if (!ctx) throw new Error("Canvas context not available");

  // Base background
  ctx.fillStyle = "#f8fafc";
  ctx.fillRect(0, 0, canvas.width, canvas.height);

  if (preset.docType === "passport") {
    // Passport Header Bar
    ctx.fillStyle = "#1e3a8a"; // Deep navy
    ctx.fillRect(20, 20, 860, 70);

    ctx.fillStyle = "#ffffff";
    ctx.font = "bold 20px sans-serif";
    ctx.fillText("भारत गणराज्य / REPUBLIC OF INDIA", 45, 50);
    ctx.font = "14px sans-serif";
    ctx.fillText("पासपोर्ट / PASSPORT", 45, 74);

    // Inner card border
    ctx.strokeStyle = "#cbd5e1";
    ctx.lineWidth = 2;
    ctx.strokeRect(20, 90, 860, 460);

    // Portrait Photo Box
    const isTampered = preset.id === "passport_tampered";
    ctx.fillStyle = isTampered ? "#fef08a" : "#e2e8f0";
    ctx.fillRect(50, 120, 180, 230);
    ctx.strokeStyle = isTampered ? "#dc2626" : "#94a3b8";
    ctx.lineWidth = isTampered ? 3 : 1;
    ctx.strokeRect(50, 120, 180, 230);

    // Silhouette / Portrait Icon
    ctx.fillStyle = isTampered ? "#b45309" : "#64748b";
    ctx.beginPath();
    ctx.arc(140, 195, 45, 0, Math.PI * 2);
    ctx.fill();
    ctx.beginPath();
    ctx.arc(140, 310, 70, Math.PI, 0, false);
    ctx.fill();

    if (isTampered) {
      ctx.fillStyle = "#dc2626";
      ctx.font = "bold 13px sans-serif";
      ctx.fillText("[SPLICED PHOTO]", 70, 340);
    }

    // Passport Details
    ctx.fillStyle = "#0f172a";
    ctx.font = "bold 13px sans-serif";

    ctx.fillText("Type / प्रकार: P", 270, 135);
    ctx.fillText("Code / कोड: IND", 450, 135);
    ctx.fillText(`Passport No / पासपोर्ट क्र.: ${preset.docNumber}`, 620, 135);

    ctx.font = "12px sans-serif";
    ctx.fillStyle = "#64748b";
    ctx.fillText("Surname / उपनाम:", 270, 170);
    ctx.fillStyle = "#0f172a";
    ctx.font = "bold 15px sans-serif";
    ctx.fillText(preset.id === "passport_syndicate" ? "KUMAR" : "ERIKSSON", 270, 190);

    ctx.font = "12px sans-serif";
    ctx.fillStyle = "#64748b";
    ctx.fillText("Given Name(s) / दिया गया नाम:", 270, 220);
    ctx.fillStyle = "#0f172a";
    ctx.font = "bold 15px sans-serif";
    ctx.fillText(preset.id === "passport_syndicate" ? "AMIT" : "ANNA MARIA", 270, 240);

    ctx.font = "12px sans-serif";
    ctx.fillStyle = "#64748b";
    ctx.fillText("Nationality / राष्ट्रीयता:", 270, 270);
    ctx.fillStyle = "#0f172a";
    ctx.font = "bold 14px sans-serif";
    ctx.fillText("INDIAN", 270, 290);

    ctx.fillStyle = "#64748b";
    ctx.fillText("Date of Birth / जन्म तिथि:", 450, 270);
    ctx.fillStyle = "#0f172a";
    ctx.font = "bold 14px sans-serif";
    ctx.fillText("06/08/1969", 450, 290);

    ctx.fillStyle = "#64748b";
    ctx.fillText("Sex / लिंग:", 640, 270);
    ctx.fillStyle = "#0f172a";
    ctx.font = "bold 14px sans-serif";
    ctx.fillText("F", 640, 290);

    ctx.fillStyle = "#64748b";
    ctx.fillText("Date of Expiry / समाप्ति तिथि:", 450, 320);
    ctx.fillStyle = "#0f172a";
    ctx.font = "bold 14px sans-serif";
    ctx.fillText("23/06/2034", 450, 340);

    // MRZ Zone Background
    ctx.fillStyle = "#f1f5f9";
    ctx.fillRect(35, 410, 830, 120);
    ctx.strokeStyle = "#cbd5e1";
    ctx.strokeRect(35, 410, 830, 120);

    // MRZ Lines (OCR-B font simulation)
    ctx.font = "24px monospace";
    ctx.fillStyle = "#0f172a";

    const line1 =
      preset.id === "passport_syndicate"
        ? "P<INDKUMAR<<AMIT<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
        : "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<";

    // Tampered changes checkdigit from 1 to 9
    const line2 = isTampered
      ? "L898902C<3UTO6908069F9406236ZE184226B<<<<<14"
      : "L898902C<3UTO6908061F9406236ZE184226B<<<<<14";

    ctx.fillText(line1, 50, 460);
    ctx.fillText(line2, 50, 505);
  } else if (preset.docType === "driving_licence") {
    // Driving Licence Layout
    ctx.fillStyle = "#047857"; // Emerald Green
    ctx.fillRect(20, 20, 860, 65);

    ctx.fillStyle = "#ffffff";
    ctx.font = "bold 18px sans-serif";
    ctx.fillText("UNION OF INDIA DRIVING LICENCE", 45, 50);
    ctx.font = "13px sans-serif";
    ctx.fillText("MINISTRY OF ROAD TRANSPORT & HIGHWAYS (MoRTH)", 45, 72);

    ctx.strokeStyle = "#cbd5e1";
    ctx.strokeRect(20, 85, 860, 470);

    // Photo Box
    ctx.fillStyle = "#e2e8f0";
    ctx.fillRect(50, 115, 170, 210);
    ctx.strokeRect(50, 115, 170, 210);

    ctx.fillStyle = "#475569";
    ctx.beginPath();
    ctx.arc(135, 180, 40, 0, Math.PI * 2);
    ctx.fill();
    ctx.beginPath();
    ctx.arc(135, 290, 65, Math.PI, 0, false);
    ctx.fill();

    ctx.fillStyle = "#0f172a";
    ctx.font = "bold 16px sans-serif";
    ctx.fillText(`Licence No: ${preset.docNumber}`, 260, 140);

    ctx.font = "13px sans-serif";
    ctx.fillStyle = "#64748b";
    ctx.fillText("Name: SASHIKANT PATEL", 260, 180);
    ctx.fillText("Son/Daughter of: RAMESH PATEL", 260, 210);
    ctx.fillText("Date of Birth: 12/04/1988", 260, 240);
    ctx.fillText("Vehicle Class: LMV, MCWG", 260, 270);
    ctx.fillText("Valid Till (NT): 11/04/2038", 260, 300);
    ctx.fillText("Issuing Authority: DL-04 RTO JANAKPURI DELHI", 260, 330);
  } else {
    // PAN Card Layout
    ctx.fillStyle = "#1e293b"; // Dark Slate
    ctx.fillRect(20, 20, 860, 65);

    ctx.fillStyle = "#ffffff";
    ctx.font = "bold 18px sans-serif";
    ctx.fillText("INCOME TAX DEPARTMENT / आयकर विभाग", 45, 50);
    ctx.font = "13px sans-serif";
    ctx.fillText("GOVERNMENT OF INDIA / भारत सरकार", 45, 72);

    ctx.strokeStyle = "#cbd5e1";
    ctx.strokeRect(20, 85, 860, 470);

    // Photo Box
    ctx.fillStyle = "#e2e8f0";
    ctx.fillRect(50, 115, 160, 200);
    ctx.strokeRect(50, 115, 160, 200);

    ctx.fillStyle = "#475569";
    ctx.beginPath();
    ctx.arc(130, 180, 38, 0, Math.PI * 2);
    ctx.fill();
    ctx.beginPath();
    ctx.arc(130, 280, 60, Math.PI, 0, false);
    ctx.fill();

    ctx.fillStyle = "#0f172a";
    ctx.font = "bold 15px sans-serif";
    ctx.fillText("Permanent Account Number / स्थायी खाता संख्या:", 250, 140);
    ctx.font = "bold 22px monospace";
    ctx.fillText(preset.docNumber, 250, 175);

    ctx.font = "13px sans-serif";
    ctx.fillStyle = "#64748b";
    ctx.fillText("Name: ANANYA CHATTERJEE", 250, 220);
    ctx.fillText("Father's Name: SUBRATA CHATTERJEE", 250, 250);
    ctx.fillText("Date of Birth: 24/09/1995", 250, 280);

    // Hologram / QR Code Placeholder
    ctx.fillStyle = "#cbd5e1";
    ctx.fillRect(720, 120, 120, 120);
    ctx.fillStyle = "#334155";
    ctx.font = "bold 11px sans-serif";
    ctx.fillText("SECURE QR", 745, 185);
  }

  // Watermark for demo
  ctx.fillStyle = "rgba(100, 116, 139, 0.15)";
  ctx.font = "bold 32px sans-serif";
  ctx.fillText("SSB NISCHAY · TEST SPECIMEN", 200, 390);

  return new Promise((resolve, reject) => {
    canvas.toBlob((blob) => {
      if (!blob) return reject(new Error("Canvas toBlob failed"));
      const file = new File([blob], preset.filename, { type: "image/png" });
      resolve(file);
    }, "image/png");
  });
}
