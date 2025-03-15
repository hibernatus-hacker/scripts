
# scan cidr ranges using masscan
# add cidrs to the ips.txt file
# compile masscan and put the binary in this directory
#
# elixir cidrscanner.exs

Mix.install([
  {:httpoison, "~> 1.8"},
  {:floki, "~> 0.32.0"},
  {:sweet_xml, "~> 0.7.5"},
  {:x509, "~> 0.8.5"},  # Add X509 library for better certificate handling
  {:jason, "~> 1.4"}    # Add Jason for JSON handling
])

defmodule SSLChecker do
  @moduledoc """
  SSL certificate checker that extracts domains and website content.
  """

  defstruct ssl_port: 443,
            mass_scan_results_file: "masscanResults.txt",
            ips_file: "ips.txt",
            masscan_rate: 10000,
            timeout: 5000,
            chunk_size: 50,
            max_concurrent: 10,
            semaphore_limit: 5,
            ports: [80],
            protocols: ["http://", "https://"]

  @doc """
  Initialize the SSL checker with default or custom options.
  """
  def new(opts \\ []) do
    struct(__MODULE__, opts)
  end

  @doc """
  Checks if a domain name is valid.
  """
  def is_valid_domain(common_name) do
    domain_pattern = ~r/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/
    Regex.match?(domain_pattern, common_name)
  end

  @doc """
  Makes an HTTP GET request to a URL and processes the response with better error handling.
  """
  def make_get_request(protocol, ip, common_name, port, make_request_by_ip \\ true) do
    url = if make_request_by_ip do
      "#{protocol}#{ip}:#{port}"
    else
      "#{protocol}#{common_name}:#{port}"
    end

    try do
      case HTTPoison.get(url, [], [
        timeout: 5000,
        recv_timeout: 8000,
        follow_redirect: true,
        max_redirect: 5,
        ssl: [verify: :verify_none],
        hackney: [pool: false]  # Disable connection pooling to avoid reusing closed connections
      ]) do
        {:ok, %HTTPoison.Response{status_code: status_code, body: body, headers: headers}} when status_code in 200..399 ->
          content_type = headers
            |> Enum.find(fn {key, _} -> String.downcase(key) == "content-type" end)
            |> case do
              {_, value} -> value
              nil -> ""
            end

          {title, first_300_words} = parse_response_content(body, content_type)

          if make_request_by_ip do
            IO.puts("Successfully requested #{url} - Status: #{status_code}")
            IO.puts("Title: #{title}")
          else
            IO.puts("Successfully requested #{common_name} - Status: #{status_code}")
            IO.puts("Title: #{title}")
          end

          response_headers = headers
            |> Enum.map(fn {key, value} -> {key, value} end)
            |> Map.new()

          %{
            "title" => title,
            "request" => url,
            "redirected_url" => "", # We'd need to track redirects manually
            "ip" => ip,
            "port" => "#{port}",
            "domain" => common_name,
            "response_text" => first_300_words,
            "response_headers" => response_headers
          }

        {:ok, %HTTPoison.Response{status_code: status_code}} ->
          IO.puts("Non-success status code for #{url}: #{status_code}")
          nil

        {:error, %HTTPoison.Error{reason: :closed}} ->
          # Handle closed connections specifically
          nil

        {:error, %HTTPoison.Error{reason: :connect_timeout}} ->
          # Handle timeout connections specifically
          nil

        {:error, %HTTPoison.Error{reason: reason}} ->
          error_message = case reason do
            {:max_redirect_overflow, _} -> "Too many redirects"
            _ -> inspect(reason)
          end
          IO.puts("Error requesting #{url}: #{error_message}")
          nil
      end
    rescue
      e ->
        IO.puts("Unexpected error for #{url}: #{inspect(e)}")
        nil
    catch
      kind, value ->
        IO.puts("Caught #{kind} for #{url}: #{inspect(value)}")
        nil
    end
  end

  @doc """
  Parses the response content based on content type.
  """
  def parse_response_content(body, content_type) do
    try do
      cond do
        String.contains?(content_type, "xml") ->
          import SweetXml
          words = body
            |> SweetXml.parse()
            |> SweetXml.xpath(~x"//text()"sl)
            |> Enum.join(" ")
            |> String.split()
            |> Enum.take(300)
            |> Enum.join(" ")
          {"", words}

        String.contains?(content_type, "html") ->
          case Floki.parse_document(body) do
            {:ok, document} ->
              title = document
                |> Floki.find("title")
                |> Floki.text()
                |> String.trim()

              body_text = document
                |> Floki.find("body")
                |> Floki.text()
                |> String.trim()
                |> String.split()
                |> Enum.take(300)
                |> Enum.join(" ")

              # If no body or title found, just take first 300 words of the document
              body_text = if body_text == "", do: 
                body
                |> String.split()
                |> Enum.take(300)
                |> Enum.join(" "), 
                else: body_text

              {title, body_text}
            _ -> 
              {"", String.split(body) |> Enum.take(300) |> Enum.join(" ")}
          end

        String.contains?(content_type, "plain") ->
          words = body
            |> String.split()
            |> Enum.take(300)
            |> Enum.join(" ")
          {"", words}

        String.contains?(content_type, "json") ->
          {first_300_chars, _} = String.split_at(body, 300)
          {"", first_300_chars}

        true ->
          words = body
            |> String.split()
            |> Enum.take(300)
            |> Enum.join(" ")
          {"", words}
      end
    rescue
      e -> 
        IO.puts("Error parsing content: #{inspect(e)}")
        {"", ""}
    end
  end

  @doc """
  Checks a site by making HTTP requests to it.
  """
  def check_site(ip, cert_info, checker) do
    common_name = cert_info["common_name"]
    alt_names = cert_info["subject_alt_names"] || []
    
    try do
      temp_dict = %{}

      temp_dict = if is_nil(common_name) || String.contains?(common_name, "*") || !is_valid_domain(common_name) do
        # Make requests using IP for both HTTP and HTTPS
        Enum.reduce(checker.protocols, temp_dict, fn protocol, acc ->
          protocol_key = "#{String.replace(protocol, "://", "")}_responseForIP"
          
          if protocol == "http://" do
            # For HTTP, try all configured ports
            http_results = Enum.map(checker.ports, fn port ->
              make_get_request(protocol, ip, common_name, port, true)
            end)
            |> Enum.filter(&(&1 != nil))
            
            if Enum.empty?(http_results) do
              acc
            else
              Map.put(acc, protocol_key, http_results)
            end
          else
            # For HTTPS, use the SSL port
            result = make_get_request(protocol, ip, common_name, checker.ssl_port, true)
            if result, do: Map.put(acc, protocol_key, result), else: acc
          end
        end)
      else
        # Make requests using both domain name and IP
        temp = Enum.reduce(checker.protocols, temp_dict, fn protocol, acc ->
          protocol_key = "#{String.replace(protocol, "://", "")}_responseForDomainName"
          port = if protocol == "http://", do: 80, else: checker.ssl_port
          result = make_get_request(protocol, ip, common_name, port, false)
          if result, do: Map.put(acc, protocol_key, result), else: acc
        end)
        
        # Also make requests using IP
        Enum.reduce(checker.protocols, temp, fn protocol, acc ->
          protocol_key = "#{String.replace(protocol, "://", "")}_responseForIP"
          
          if protocol == "http://" do
            # For HTTP, try all configured ports
            http_results = Enum.map(checker.ports, fn port ->
              make_get_request(protocol, ip, common_name, port, true)
            end)
            |> Enum.filter(&(&1 != nil))
            
            if Enum.empty?(http_results) do
              acc
            else
              Map.put(acc, protocol_key, http_results)
            end
          else
            # For HTTPS, use the SSL port
            result = make_get_request(protocol, ip, common_name, checker.ssl_port, true)
            if result, do: Map.put(acc, protocol_key, result), else: acc
          end
        end)
      end

      # Try alternative domain names if common name didn't work
      temp_dict = if Map.has_key?(temp_dict, "https_responseForDomainName") do
        temp_dict
      else
        # Try each alternative name
        Enum.reduce(alt_names, temp_dict, fn alt_name, acc ->
          if is_valid_domain(alt_name) do
            Enum.reduce(checker.protocols, acc, fn protocol, inner_acc ->
              protocol_key = "#{String.replace(protocol, "://", "")}_responseForAltName_#{alt_name}"
              port = if protocol == "http://", do: 80, else: checker.ssl_port
              result = make_get_request(protocol, ip, alt_name, port, false)
              if result, do: Map.put(inner_acc, protocol_key, result), else: inner_acc
            end)
          else
            acc
          end
        end)
      end

      # Add certificate information to the result
      temp_dict = Map.put(temp_dict, "certificate_info", cert_info)

      # Only return non-empty dictionaries
      if Enum.empty?(temp_dict), do: nil, else: temp_dict
    rescue
      e ->
        IO.puts("Exception in check_site for #{ip}: #{inspect(e)}")
        nil
    catch
      kind, value ->
        IO.puts("Caught #{kind} in check_site for #{ip}: #{inspect(value)}")
        nil
    end
  end

  @doc """
  Fetches SSL certificate for an IP address using X509 library with improved error handling.
  """
  def fetch_certificate(ip, ssl_port, timeout) do
    try do
      socket_opts = [
        :binary,
        packet: :raw,
        active: false,
        reuseaddr: true,
        verify: :verify_none
      ]

      case :ssl.connect(String.to_charlist(ip), ssl_port, socket_opts, timeout) do
        {:ok, socket} ->
          # Get the peer certificate
          cert_der = :ssl.peercert(socket)
          :ssl.close(socket)

          if cert_der do
            # Parse the certificate using X509 library with proper error handling
            try do
              cert = X509.Certificate.from_der!(cert_der)

              # Extract certificate information
              cert_info = extract_certificate_info(cert, ip)

              IO.puts("Found certificate for #{ip}:")
              IO.puts("  Common Name: #{cert_info["common_name"]}")
              IO.puts("  Organization: #{cert_info["organization"]}")
              IO.puts("  Alt Names: #{Enum.join(cert_info["subject_alt_names"] || [], ", ")}")

              {ip, cert_info}
            rescue
              e in FunctionClauseError ->
                # Handle specific error from pkix_decode_cert
                if e.module == :public_key && e.function == :pkix_decode_cert do
#                   IO.puts("Invalid certificate format for #{ip}")
                  {ip, %{"common_name" => nil, "ip" => ip}}
                else
                  reraise e, __STACKTRACE__
                end

              e ->
                IO.puts("Error parsing certificate for #{ip}: #{inspect(e)}")
                {ip, %{"common_name" => nil, "ip" => ip}}
            end
          else
            IO.puts("No certificate found for #{ip}")
            {ip, %{"common_name" => nil, "ip" => ip}}
          end

        {:error, :closed} ->
          # Handle closed connections specifically
#           IO.puts("Connection closed by #{ip}")
          {ip, %{"common_name" => nil, "ip" => ip}}

        {:error, :connect_timeout} ->
          # Handle timeout connections specifically
#           IO.puts("Connection timeout for #{ip}")
          {ip, %{"common_name" => nil, "ip" => ip}}

        {:error, _reason} ->
          # Don't log specific SSL connection errors
          {ip, %{"common_name" => nil, "ip" => ip}}
      end
    rescue
      e ->
        IO.puts("Exception in fetch_certificate for #{ip}: #{inspect(e)}")
        {ip, %{"common_name" => nil, "ip" => ip}}
    catch
      kind, value ->
        IO.puts("Caught #{kind} in fetch_certificate for #{ip}: #{inspect(value)}")
        {ip, %{"common_name" => nil, "ip" => ip}}
    after
      # Ensure we give the system a small break between SSL connections
      Process.sleep(100)
    end
  end

  @doc """
  Extracts detailed information from an X509 certificate with better error handling.
  """
  def extract_certificate_info(cert, ip) do
    try do
      # Extract subject
      subject = X509.Certificate.subject(cert)

      # Extract common name
      common_name = try do
        X509.RDNSequence.get_attr(subject, :commonName)
      rescue
        _ -> nil
      end

      # Extract organization
      organization = try do
        X509.RDNSequence.get_attr(subject, :organizationName)
      rescue
        _ -> nil
      end

      # Extract subject alternative names
      alt_names = try do
        extensions = X509.Certificate.extensions(cert)
        case X509.Certificate.Extension.find(extensions, :subjectAltName) do
          nil -> []
          extension ->
            X509.Certificate.Extension.subject_alt_name(extension)
            |> Enum.map(fn
              {:dNSName, name} -> to_string(name)
              _ -> nil
            end)
            |> Enum.filter(&(&1 != nil))
        end
      rescue
        _ -> []
      end

      # Extract validity dates
      {not_before, not_after} = try do
        validity = X509.Certificate.validity(cert)
        {validity[:not_before], validity[:not_after]}
      rescue
        _ -> {nil, nil}
      end

      # Extract issuer
      {issuer_cn, issuer_org} = try do
        issuer = X509.Certificate.issuer(cert)
        {
          X509.RDNSequence.get_attr(issuer, :commonName),
          X509.RDNSequence.get_attr(issuer, :organizationName)
        }
      rescue
        _ -> {nil, nil}
      end

      # Create certificate info map
      %{
        "common_name" => common_name && to_string(common_name),
        "organization" => organization && to_string(organization),
        "subject_alt_names" => alt_names,
        "issuer_common_name" => issuer_cn && to_string(issuer_cn),
        "issuer_organization" => issuer_org && to_string(issuer_org),
        "not_before" => format_date(not_before),
        "not_after" => format_date(not_after),
        "ip" => ip
      }
    rescue
      e ->
        IO.puts("Error extracting certificate info: #{inspect(e)}")
        %{"common_name" => nil, "ip" => ip}
    end
  end
  
  @doc """
  Formats a date for display.
  """
  def format_date(nil), do: nil
  def format_date(date) do
    case date do
      {{year, month, day}, {hour, minute, second}} ->
        "#{year}-#{pad(month)}-#{pad(day)} #{pad(hour)}:#{pad(minute)}:#{pad(second)}"
      _ -> to_string(date)
    end
  end
  
  defp pad(num) when num < 10, do: "0#{num}"
  defp pad(num), do: to_string(num)

  @doc """
  Process a chunk of IPs with better error handling.
  """
  def process_ip_chunk(chunk_of_ips, checker) do
    IO.puts("Processing chunk of #{length(chunk_of_ips)} IPs")
    
    # Fetch certificates for all IPs in the chunk with better error handling
    ip_and_cert_infos = 
      chunk_of_ips
      |> Enum.map(fn ip ->
        # Add a small delay between requests to avoid overwhelming the system
        Process.sleep(50)
        
        task = Task.async(fn -> 
          fetch_certificate(ip, checker.ssl_port, checker.timeout)
        end)
        
        try do
          Task.await(task, checker.timeout * 2)
        rescue
          e -> 
            IO.puts("Error awaiting certificate task for #{ip}: #{inspect(e)}")
            {ip, %{"common_name" => nil, "ip" => ip}}
        catch
          :exit, _ -> 
            IO.puts("Timeout fetching certificate for #{ip}")
            Task.shutdown(task, :brutal_kill)
            {ip, %{"common_name" => nil, "ip" => ip}}
        end
      end)
    
    IO.puts("Fetched #{length(ip_and_cert_infos)} certificates")
    
    # Check sites for all IPs with their certificate information
    all_responses = 
      ip_and_cert_infos
      |> Enum.map(fn {ip, cert_info} ->
        # Add a small delay between requests to avoid overwhelming the system
        Process.sleep(100)
        
        task = Task.async(fn -> 
          check_site(ip, cert_info, checker)
        end)
        
        try do
          result = Task.await(task, checker.timeout * 4)
          if result, do: result, else: nil
        rescue
          e -> 
            IO.puts("Error awaiting check_site task for #{ip}: #{inspect(e)}")
            nil
        catch
          :exit, _ -> 
            IO.puts("Timeout checking site for #{ip}")
            Task.shutdown(task, :brutal_kill)
            nil
        end
      end)
      |> Enum.filter(&(&1 != nil))
    
    IO.puts("Processed #{length(all_responses)} successful responses")
    
    # Print results to console
    if Enum.empty?(all_responses) do
      IO.puts("No successful responses in this chunk")
    else
      IO.puts("****************Results processed successfully**************")
      IO.inspect(all_responses, pretty: true, limit: :infinity)
    end
    
    all_responses
  end

  @doc """
  Extracts domains from IP addresses in the masscan results file.
  """
  def extract_domains(checker) do
    # Read IP addresses from the masscan results file
    ip_addresses = case File.read(checker.mass_scan_results_file) do
      {:ok, content} -> extract_ips(content)
      {:error, _} -> 
        IO.puts("Warning: Could not read masscan results file. Using sample IPs for testing.")
        ["8.8.8.8", "1.1.1.1", "142.250.185.78"] # Sample IPs for testing
    end

    IO.puts("Found #{length(ip_addresses)} IP addresses to process")

    # Process IPs in chunks
    results = 
      ip_addresses
      |> Enum.chunk_every(checker.chunk_size)
      |> Enum.flat_map(fn chunk ->
        process_ip_chunk(chunk, checker)
      end)

    # Print summary
    IO.puts("\n=== Summary ===")
    IO.puts("Total IPs processed: #{length(ip_addresses)}")
    IO.puts("Successful responses: #{length(results)}")
    
    # Extract unique domains from results
    domains = extract_unique_domains(results)
    IO.puts("Unique domains found: #{length(domains)}")
    
    if length(domains) > 0 do
      IO.puts("\n=== Domains Found ===")
      Enum.each(domains, fn domain -> IO.puts(domain) end)
      
      # Save domains to file
      save_domains_to_file(domains, "domains_found.txt")
    end
    
    # Save full results to JSON file
    save_results_to_json(results, "scan_results.json")
    
    results
  end
  
  @doc """
  Extracts unique domains from the results.
  """
  def extract_unique_domains(results) do
    # Extract domains from certificate info
    cert_domains = results
    |> Enum.flat_map(fn result ->
      cert_info = result["certificate_info"]
      if cert_info do
        [cert_info["common_name"] | (cert_info["subject_alt_names"] || [])]
      else
        []
      end
    end)
    
    # Extract domains from HTTP responses
    response_domains = results
    |> Enum.flat_map(fn result ->
      # Extract domain from each result
      Map.keys(result)
      |> Enum.filter(fn key -> 
        String.contains?(key, "response") && !String.contains?(key, "certificate_info")
      end)
      |> Enum.flat_map(fn key ->
        case result[key] do
          responses when is_list(responses) ->
            # Handle case where we have a list of responses
            Enum.map(responses, fn r -> r["domain"] end)
          response when is_map(response) ->
            # Handle case where we have a single response
            [response["domain"]]
          _ -> []
        end
      end)
    end)
    
    # Combine all domains and filter valid ones
    (cert_domains ++ response_domains)
    |> Enum.filter(fn domain -> 
      domain && domain != "" && !String.contains?(domain || "", "*") && is_valid_domain(domain || "")
    end)
    |> Enum.uniq()
    |> Enum.sort()
  end
  
  @doc """
  Saves domains to a text file.
  """
  def save_domains_to_file(domains, filename) do
    content = Enum.join(domains, "\n")
    case File.write(filename, content) do
      :ok -> 
        IO.puts("Domains saved to #{filename}")
        :ok
      {:error, reason} -> 
        IO.puts("Error saving domains to file: #{inspect(reason)}")
        :error
    end
  end
  
  @doc """
  Saves results to a JSON file.
  """
  def save_results_to_json(results, filename) do
    case Jason.encode(results, pretty: true) do
      {:ok, json} ->
        case File.write(filename, json) do
          :ok -> 
            IO.puts("Results saved to #{filename}")
            :ok
          {:error, reason} -> 
            IO.puts("Error saving results to file: #{inspect(reason)}")
            :error
        end
      {:error, reason} ->
        IO.puts("Error encoding results to JSON: #{inspect(reason)}")
        :error
    end
  end
  
  @doc """
  Extracts the domain name from a URL.
  """
  def extract_domain_from_url(url) do
    # Remove protocol if present
    domain = url
      |> String.replace(~r{^https?://}, "")
      |> String.replace(~r{^.*@}, "")  # Remove username/password if present
      
    # Extract domain part (before path or port)
    domain = case String.split(domain, ["/", ":"]) do
      [domain | _] -> domain
      [] -> ""
    end
    
    domain
  end
  
  @doc """
  Extracts IP addresses from text.
  """
  def extract_ips(text) do
    ~r/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/
    |> Regex.scan(text)
    |> List.flatten()
  end

  @doc """
  Runs masscan to find open ports.
  """
  def run_masscan(checker) do
    command = "sudo ./masscan -p443 --rate #{checker.masscan_rate} --wait 0 -iL #{checker.ips_file} -oH #{checker.mass_scan_results_file}"
    
    case System.cmd("sh", ["-c", command], stderr_to_stdout: true) do
      {_output, 0} ->
        IO.puts("Masscan completed successfully")
        :ok
      {error, _} ->
        IO.puts("Error while running masscan: #{error}")
        :error
    end
  end

  @doc """
  Checks if files exist and creates them if they don't.
  """
  def check_and_create_files(files) do
    Enum.each(files, fn file_path ->
      unless File.exists?(file_path) do
        File.touch!(file_path)
        IO.puts("File \"#{file_path}\" has been created.")
      end
    end)
  end

  @doc """
  Main function to run the SSL checker.
  """
  def main(checker) do
    check_and_create_files([checker.mass_scan_results_file, checker.ips_file])
    # Uncomment to run masscan
    run_masscan(checker)
    extract_domains(checker)
  end
end

# Application entry point
defmodule SSLCheckerApp do
  def main(_args \\ []) do
    # Initialize HTTPoison
    HTTPoison.start()
    
    # Create a new SSL checker with default settings
    checker = SSLChecker.new()
    
    # Run the main function
    SSLChecker.main(checker)
  end
end

# Run the application
SSLCheckerApp.main()
