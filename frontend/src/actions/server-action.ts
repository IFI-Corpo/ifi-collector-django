export const serverAction = async (formData: any) => {
  // Here you would handle your server-side action (e.g., submitting the data to an API)
  console.log("Form submitted with data:", formData);
  return new Promise((resolve) => setTimeout(resolve, 2000)); // Simulate network delay
};
