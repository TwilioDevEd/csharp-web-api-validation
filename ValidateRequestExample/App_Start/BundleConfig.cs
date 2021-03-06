﻿using System.Web;
using System.Web.Optimization;

namespace ValidateRequestExample
{
    public class BundleConfig
    {
        // For more information on bundling, visit https://go.microsoft.com/fwlink/?LinkId=301862
        public static void RegisterBundles(BundleCollection bundles)
        {
            bundles.Add(new ScriptBundle("~/bundles/scripts").Include(
                      "~/Scripts/lib/dist/js/bootstrap.js",
                      "~/Scripts/lib/dist/js/jquery.js"));

            bundles.Add(new StyleBundle("~/Content/css").Include(
                      "~/Scripts/lib/dist/css/bootstrap.css",
                      "~/Content/site.css"));
        }
    }
}
