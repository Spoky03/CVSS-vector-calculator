"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { Button } from "@/components/ui/button";
import {
  Form,
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { postRequest } from "./lib/requests";
import type { PredictionResponse } from "./lib/interfaces";
import { Textarea } from "./components/ui/textarea";
const formSchema = z.object({
  description: z.string().min(10, {
    message: "Description must be at least 10 characters.",
  }),
});

export function DescriptionForm({setLoading, setResponseData} : {
    setLoading: (loading: boolean) => void;
    setResponseData: (data: PredictionResponse | null) => void;
} ) {
  // This component is a form for submitting a vulnerability description.
  // 1. Define your form.
  const form = useForm<z.infer<typeof formSchema>>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      description: "",
    },
  });

  // 2. Define a submit handler.
  function onSubmit(values: z.infer<typeof formSchema>) {
    // Do something with the form values.
    // ✅ This will be type-safe and validated.
    console.log("Form submitted:", values);
    setLoading(true);
    // send request to the server
    postRequest("/predict", values)
      .then((response) => {
        console.log("Response:", response);
        // Handle successful response
        setResponseData(response.data);
        setLoading(false);
      })
      .catch((error) => {
        console.error("Error:", error);
        // Handle error
        setResponseData(null);
      });
  }

  

  return (
    <div className="space-y-12">
      <Form {...form}>
        <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-8">
          <FormField
            control={form.control}
            name="description"
            render={({ field }) => (
              <FormItem className="space-y-2 mt-4">
                <FormLabel className="hidden">Description</FormLabel>
                <FormControl>
                  <Textarea
                    placeholder="Describe the vulnerability in detail..."
                    {...field}
                    className="resize-none h-48"
                  />
                </FormControl>
                <FormDescription>
                  Provide a detailed description of the vulnerability.
                </FormDescription>
                <FormMessage />
              </FormItem>
            )}
          />
          <Button type="submit" className="w-full">
            Submit
          </Button>
        </form>
      </Form>
    </div>
  );
}
