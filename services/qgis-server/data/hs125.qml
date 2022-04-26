<!DOCTYPE qgis PUBLIC 'http://mrcc.com/qgis.dtd' 'SYSTEM'>
<qgis styleCategories="AllStyleCategories" minScale="1e+08" hasScaleBasedVisibilityFlag="0" version="3.22.1-Białowieża" maxScale="0">
  <flags>
    <Identifiable>1</Identifiable>
    <Removable>1</Removable>
    <Searchable>1</Searchable>
    <Private>0</Private>
  </flags>
  <temporal fetchMode="0" enabled="0" mode="0">
    <fixedRange>
      <start></start>
      <end></end>
    </fixedRange>
  </temporal>
  <customproperties>
    <Option type="Map">
      <Option value="false" name="WMSBackgroundLayer" type="bool"/>
      <Option value="false" name="WMSPublishDataSourceUrl" type="bool"/>
      <Option value="0" name="embeddedWidgets/count" type="int"/>
      <Option value="Value" name="identify/format" type="QString"/>
    </Option>
  </customproperties>
  <pipe-data-defined-properties>
    <Option type="Map">
      <Option value="" name="name" type="QString"/>
      <Option name="properties"/>
      <Option value="collection" name="type" type="QString"/>
    </Option>
  </pipe-data-defined-properties>
  <pipe>
    <provider>
      <resampling zoomedInResamplingMethod="nearestNeighbour" enabled="false" zoomedOutResamplingMethod="nearestNeighbour" maxOversampling="2"/>
    </provider>
    <rasterrenderer nodataColor="" opacity="1" grayBand="1" gradient="BlackToWhite" type="singlebandgray" alphaBand="-1">
      <rasterTransparency/>
      <minMaxOrigin>
        <limits>None</limits>
        <extent>WholeRaster</extent>
        <statAccuracy>Estimated</statAccuracy>
        <cumulativeCutLower>0.02</cumulativeCutLower>
        <cumulativeCutUpper>0.98</cumulativeCutUpper>
        <stdDevFactor>2</stdDevFactor>
      </minMaxOrigin>
      <contrastEnhancement>
        <minValue>25</minValue>
        <maxValue>225</maxValue>
        <algorithm>StretchToMinimumMaximum</algorithm>
      </contrastEnhancement>
      <rampLegendSettings minimumLabel="" useContinuousLegend="1" maximumLabel="" direction="0" suffix="" prefix="" orientation="2">
        <numericFormat id="basic">
          <Option type="Map">
            <Option value="" name="decimal_separator" type="QChar"/>
            <Option value="6" name="decimals" type="int"/>
            <Option value="0" name="rounding_type" type="int"/>
            <Option value="false" name="show_plus" type="bool"/>
            <Option value="true" name="show_thousand_separator" type="bool"/>
            <Option value="false" name="show_trailing_zeros" type="bool"/>
            <Option value="" name="thousand_separator" type="QChar"/>
          </Option>
        </numericFormat>
      </rampLegendSettings>
    </rasterrenderer>
    <brightnesscontrast contrast="0" brightness="0" gamma="1"/>
    <huesaturation colorizeOn="0" colorizeStrength="100" invertColors="0" colorizeRed="255" colorizeBlue="128" colorizeGreen="128" saturation="0" grayscaleMode="0"/>
    <rasterresampler maxOversampling="2"/>
    <resamplingStage>resamplingFilter</resamplingStage>
  </pipe>
  <blendMode>0</blendMode>
</qgis>
